# CyberLLM

A dataset of 54,928 instruction-response pairs for analyzing safety implications of fine-tuning LLMs on cybersecurity data.

## Repository Structure

* `CyberMetric/`: CyberMetric evaluation framework and benchmarks
* `dataset/`: The CyberLLM dataset files
* `dataset_creation/`: Scripts for dataset creation, reproduction, and expansion
* `DeepEval/`: DeepEval evaluation setup and results
  - `test.py`: Main evaluation script
  - `run.sh`: Evaluation runner
  - `*.out`: Evaluation outputs
* `Finetune/`: Fine-tuning implementation
  - `finetune.py`: Fine-tuning script
  - `infer.py`: Inference script
* `scripts/`: Additional utility scripts
  - Data categorization
  - Processing tools

## Citation
