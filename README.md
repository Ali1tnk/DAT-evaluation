# DAT-evaluation

This repository contains tools and scripts for evaluating attack trees using TAPAAL-based simulations.

## Structure

- `generate_trees.py`: Generates attack tree structures.
- `run_tapaal.sh`: Executes TAPAAL simulations.
- `plot_results.py`: Visualizes simulation outcomes.
- `use_case.py`: Defines a specific use case scenario.
- `use_case_report.py`: Summarizes results and analysis.
- `lib/`: Contains reusable modules:
  - `tapaal.py`: TAPAAL XML generation and interface.
  - `trees.py`: Attack tree utilities.
  - `__init__.py`: Package initializer.
- `requirements.txt`: Python dependencies.

## Usage

Run `run_tapaal.sh` after generating trees to simulate and analyze results.

## License

MIT (or specify your license here)


