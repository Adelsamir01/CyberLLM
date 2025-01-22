# CyberLLM

Code and dataset repository for the paper:
> CyberLLM: A new dataset for analysing safety of fine-tuned LLMs using cyber security data

This repository contains all code, dataset, and materials used in the paper.

## Repository Structure

* `cybermetric/`: CyberMetric evaluation framework and benchmarks
* `dataset/`: The CyberLLM dataset files
* `dataset_creation/`: Dataset creation pipeline
  - Eight sequential scripts (`1_data_collector.py` through `8_final_assembler.py`) for collecting, processing, and validating cyber security data
  - See [`dataset_creation/README.md`](dataset_creation/README.md) for detailed pipeline documentation
* `deepeval/`: DeepEval evaluation setup and results
  - `test.py`: Main evaluation script
  - `run.sh`: Evaluation runner
  - `*.out`: Evaluation outputs
* `finetune/`: Fine-tuning implementation
  - `finetune.py`: Fine-tuning script
  - `infer.py`: Inference script
* `scripts/`: Utility scripts for dataset management
  - `categorise.py`: Pattern-based domain categorisation
  - `dataset_export.py`: Dataset export and platform upload
  - See [`scripts/README.md`](scripts/README.md) for usage instructions
