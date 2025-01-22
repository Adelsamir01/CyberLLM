# CyberLLM

Code and dataset repository for the paper:
> CyberLLM: A new dataset for analysing safety of fine-tuned LLMs using cyber security data

This repository contains all code, dataset, and materials used in the paper.
## Repository Structure

* `cybermetric/`: CyberMetric evaluation framework and benchmarks
* `dataset/`: The CyberLLM dataset files
* `dataset_creation/`: Scripts for dataset creation, reproduction, and expansion
* `deepeval/`: DeepEval evaluation setup and results
  - `test.py`: Main evaluation script
  - `run.sh`: Evaluation runner
  - `*.out`: Evaluation outputs
* `finetune/`: Fine-tuning implementation
  - `finetune.py`: Fine-tuning script
  - `infer.py`: Inference script
* `scripts/`: Additional utility scripts
  - Data categorisation
