"""Deterministic domain folds that balance domain coverage before row counts."""

import numpy as np


def domain_folds(labels, groups, n_splits=5, seed=42):
    """Return complete, non-overlapping held-out index arrays.

    Within each group's majority class, assign large domains first to the fold
    with the fewest domains of that class, then the fewest rows of that class.
    This deliberately prioritizes domain diversity: one very large cloud apex
    must not consume a fold's entire benign domain allocation. Mixed-label
    groups remain intact. Neither features nor model scores affect allocation.
    """
    labels = np.asarray(labels)
    groups = np.asarray(groups)
    if n_splits < 2 or len(labels) != len(groups) or not len(labels):
        raise ValueError("Require matching nonempty labels/groups and at least two folds")
    if not set(labels).issubset({0, 1}):
        raise ValueError("Labels must be 0 or 1")
    unique, inverse = np.unique(groups, return_inverse=True)
    counts = np.zeros((len(unique), 2), dtype=int)
    np.add.at(counts, (inverse, labels.astype(int)), 1)
    majority = counts.argmax(axis=1)
    if any(np.sum(majority == label) < n_splits for label in (0, 1)):
        raise ValueError("Each majority class needs at least n_splits distinct domains")
    rng = np.random.default_rng(seed)
    tie_order = rng.permutation(len(unique))
    fold_priority = rng.permutation(n_splits).tolist()
    order = sorted(tie_order, key=lambda i: -int(counts[i].sum()))
    group_counts = np.zeros((n_splits, 2), dtype=int)
    row_counts = np.zeros((n_splits, 2), dtype=int)
    allocation = np.empty(len(unique), dtype=int)
    for i in order:
        label = majority[i]
        fold = min(fold_priority, key=lambda f: (group_counts[f, label], row_counts[f, label], row_counts[f].sum()))
        allocation[i] = fold
        group_counts[fold, label] += 1
        row_counts[fold] += counts[i]
    folds = [np.flatnonzero(allocation[inverse] == f) for f in range(n_splits)]
    for indexes in folds:
        if set(labels[indexes]) != {0, 1}:
            raise ValueError("Every fold must contain both classes")
    return folds
