# Public benign input attribution

`public_benign.csv.gz` is a converted subset of the
[Daumel DNS exfiltration dataset](https://github.com/Daumel/dns-exfiltration-dataset),
distributed on [Kaggle](https://www.kaggle.com/datasets/daumel/dns-tunneling-dataset).
Kaggle distribution metadata identifies the license as
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Credit: Daumel, and the upstream university captures by Singh et al. identified
in the author's README in connection with *Detecting bot-infected machines
using DNS fingerprinting*. The original file is:

```text
dns-exfiltration-dataset/01_original_pcap_files/benign/university_traffic/monday/20160425_075435.pcap
```

Changes: select the first 200,000 packets in file order; retain valid UDP
single-question DNS requests; map names, IP addresses, timestamps, query type
and publisher benign label to the project's canonical CSV schema. Responses
and unsupported/invalid records are excluded. No model-based relabelling or
model-score-based row selection occurred. The resulting 88,139 rows are
compressed with gzip. The full raw capture is not redistributed here.

`public_benign.provenance.json` records the original and converted hashes,
packet counts, filtering counts, source path and limitations. Restore with
`python -m scripts.restore_public_benign --output <new-local-csv-path>`.

Only 85,604 of these rows enter the recorded forest experiment: every apex in
the frozen diagnostic evaluation is excluded during training. Public captures
receive separate behavioral histories, and provenance/identifiers are never
forest features. See [experiment protocol](../../docs/aws_benign_expansion.md).
