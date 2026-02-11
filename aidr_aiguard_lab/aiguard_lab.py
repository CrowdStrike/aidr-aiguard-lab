from __future__ import annotations

import sys
from typing import Annotated

import cyclopts
from cyclopts import App, Parameter

from aidr_aiguard_lab._types import AppArgs
from aidr_aiguard_lab.config.settings import Settings
from aidr_aiguard_lab.defaults import defaults
from aidr_aiguard_lab.manager.aiguard_manager import AIGuardManager, AIGuardTests

app = App(help="Process prompts with AI Guard API.\nSpecify a --prompt or --input-file", help_format="markdown")


INPUT_FILE_HELP = (
    "File containing test cases to process. Supports multiple formats:\n"
    ".txt    One prompt per line.\n"
    ".jsonl  JSON Lines format, each line is test case with labels and\n"
    "        messages array:\n"
    '        {"label": ["malicious"], "messages": [{"role": "user", '
    '"content": "prompt"}]}\n'
    ".json   JSON file with a tests array of test cases, each labels and a \n"
    "        messages array:\n"
    '        {"tests": [{"label": ["malicious"], "messages": [{"role": '
    '"user", "content": "prompt"}]}]}\n'
    "        Supports optional global settings that provide defaults for all\n"
    "        tests.\n"
    "        Each test case can specify its own settings to override global \n"
    "        ones.\n"
    "        Each test case can specify expected_detectors in addition to or \n"
    "        as an alternative to labels.\n"
)

FORCE_SYSTEM_PROMPT_HELP = (
    "Force a system prompt even if there is none in the test case\n"
    "(default: False).\n"
    "NOTE: AI Guard conformance/non-conformance checks are based on a \n"
    "      system prompt and only happen if one is present.\n"
)

DETECTORS_HELP = (
    "Comma separated list of detectors to use.\n"
    + "Default:\n  "
    + defaults.default_detectors_str.replace(", ", ",\n  ")
    + "\n"
    + "Available detectors:\n  malicious-prompt, topic:<topic-name>\n"
    # + defaults.valid_detectors_str.replace(', ', ',\n  ') + "\n"
    + "Use 'topic:<topic-name>' or just '<topic-name>' for topic detectors.\n"
    + "Available topic names:\n  "
    + defaults.valid_topics_str.replace(", ", ",\n  ")
    + "\n"
)

USE_LABELS_AS_DETECTORS_HELP = (
    "Use the labels from the test cases as topics for detection.\n"
    "This will enable all topic detectors corresponding to the labels in the test cases.\n"
    "Default: False."
)

REPORT_ANY_TOPIC_HELP = (
    "Report any topic detection, even if not specified in --detectors.\n"
    "This will report all detected topics in the response, regardless of\n"
    "whether they are explicitly requested or not. Default: False."
)

TOPIC_THRESHOLD_HELP = (
    "Threshold for topic detection confidence. Only applies when using\n"
    f"AI Guard with topics. Default: {defaults.topic_threshold}."
)

FAIL_FAST_HELP = "Enable fail-fast mode: detectors will block and exit on first\ndetection. Default: False.\n"

MALICIOUS_PROMPT_LABELS_HELP = (
    "Comma separated list of labels indicating a malicious prompt.\n"
    + "Default:\n  "
    + defaults.malicious_prompt_labels_str.replace(", ", ",\n  ")
    + "\n"
    + "Test cases with any of these labels expect the malicious-prompt\n"
    + "detector to return a detection (FN if it does not).\n"
    + "Must not overlap with --benign-labels."
)

BENIGN_LABELS_HELP = (
    "Comma separated list of labels indicating a benign prompt.\n"
    + "Default:\n  "
    + defaults.benign_labels_str.replace(", ", ",\n  ")
    + "\n"
    + "Test cases with any of these labels expect no detections \n"
    + "from any detector (FP if it does).\n"
    + "Must not overlap with --malicious_prompt_labels."
)

NEGATIVE_LABELS_HELP = (
    "Comma separated list of labels indicating negative examples for specific detectors.\n"
    "Use the pattern 'not-topic:<topic-name>' (e.g. not-topic:legal-advice).\n"
    "Test cases with any of these labels expect **no** detections from the corresponding "
    "detector (FP if it does).\n"
    "Default: not-topic:*"
)

RECIPE_HELP = (
    "The recipe to use for processing the prompt.\n"
    "Useful when using --prompt for a single prompt.\n"
    "Available recipes:\n"
    "  all\n"
    + "".join([f"  {r}\n" for r in defaults.default_recipes])
    + f"Default: {defaults.default_recipe if defaults.default_recipe else 'None'}\n"
    'Use "all" to iteratively apply all recipes to the prompt\n'
    "(only supported for --prompt).\n\n"
    "Not appliccable when using --detectors or JSON test case objects\n"
    "that override the recipe with explicit detectors."
)

AIDR_CONFIG_HELP = (
    "JSON string or path to JSON file with AIDR metadata overrides.\n"
    "Default metadata:\n"
    "  event_type: input\n"
    "  app_id: AIG-lab\n"
    "  actor_id: test tool\n"
    "  llm_provider: test\n"
    "  model: GPT-6-super\n"
    "  model_version: 6s\n"
    "  source_ip: 74.244.51.54\n"
    "  extra_info:\n"
    "    actor_name: {current_user}\n"
    "    app_name: AIGuard-lab\n\n"
    "Example JSON override:\n"
    '  --aidr-config \'{"app_id": "MyApp", "model": "GPT-4"}\'\n'
    "Or path to file:\n"
    "  --aidr-config /path/to/config.json"
)

RPS_HELP = f"Requests per second (1-100 allowed. Default: {defaults.default_rps})"
MAX_POLL_ATTEMPTS_HELP = f"Maximum poll (retry) attempts for 202 responses (default: {defaults.max_poll_attempts})"


@app.default
def main(
    # Input arguments
    prompt: Annotated[str | None, Parameter(group="Input arguments", help="A single prompt string to check")] = None,
    input_file: Annotated[str | None, Parameter(group="Input arguments", help=INPUT_FILE_HELP)] = None,
    # Detection and evaluation configuration
    system_prompt: Annotated[
        str | None,
        Parameter(
            group="Detection and evaluation configuration",
            help="The system prompt to use for processing the prompt (default: None)",
        ),
    ] = None,
    force_system_prompt: Annotated[
        bool, Parameter(group="Detection and evaluation configuration", help=FORCE_SYSTEM_PROMPT_HELP)
    ] = False,
    detectors: Annotated[
        str, Parameter(group="Detection and evaluation configuration", help=DETECTORS_HELP)
    ] = defaults.default_detectors_str,
    use_labels_as_detectors: Annotated[
        bool, Parameter(group="Detection and evaluation configuration", help=USE_LABELS_AS_DETECTORS_HELP)
    ] = False,
    report_any_topic: Annotated[
        bool, Parameter(group="Detection and evaluation configuration", help=REPORT_ANY_TOPIC_HELP)
    ] = False,
    topic_threshold: Annotated[
        float, Parameter(group="Detection and evaluation configuration", help=TOPIC_THRESHOLD_HELP)
    ] = defaults.topic_threshold,
    fail_fast: Annotated[bool, Parameter(group="Detection and evaluation configuration", help=FAIL_FAST_HELP)] = False,
    malicious_prompt_labels: Annotated[
        str, Parameter(group="Detection and evaluation configuration", help=MALICIOUS_PROMPT_LABELS_HELP)
    ] = defaults.malicious_prompt_labels_str,
    benign_labels: Annotated[
        str, Parameter(group="Detection and evaluation configuration", help=BENIGN_LABELS_HELP)
    ] = defaults.benign_labels_str,
    negative_labels: Annotated[
        str, Parameter(group="Detection and evaluation configuration", help=NEGATIVE_LABELS_HELP)
    ] = "not-topic:*",
    recipe: Annotated[
        str, Parameter(group="Detection and evaluation configuration", help=RECIPE_HELP)
    ] = defaults.default_recipe,
    aidr_config: Annotated[
        str | None, Parameter(group="Detection and evaluation configuration", help=AIDR_CONFIG_HELP)
    ] = None,
    # Output and reporting
    report_title: Annotated[
        str | None,
        Parameter(group="Output and reporting", help="Optional title in report summary"),
    ] = None,
    summary_report_file: Annotated[
        str | None,
        Parameter(group="Output and reporting", help="Optional summary report file name"),
    ] = None,
    fps_out_csv: Annotated[
        str | None,
        Parameter(group="Output and reporting", help="Output CSV for false positives"),
    ] = None,
    fns_out_csv: Annotated[
        str | None,
        Parameter(group="Output and reporting", help="Output CSV for false negatives"),
    ] = None,
    print_label_stats: Annotated[
        bool,
        Parameter(group="Output and reporting", help="Display per-label stats (FP/FN counts)"),
    ] = False,
    print_fps: Annotated[
        bool,
        Parameter(group="Output and reporting", help="Print false positives after summary"),
    ] = False,
    print_fns: Annotated[
        bool,
        Parameter(group="Output and reporting", help="Print false negatives after summary"),
    ] = False,
    verbose: Annotated[
        bool,
        Parameter(group="Output and reporting", help="Enable verbose output (FPs, FNs as they occur, full errors)."),
    ] = False,
    debug: Annotated[
        bool,
        Parameter(group="Output and reporting", help="Enable debug output (default: False)"),
    ] = False,
    # Assumptions for plain text prompts
    assume_tps: Annotated[
        bool,
        Parameter(group="Assumptions for plain text prompts", help="Assume all inputs are true positives"),
    ] = False,
    assume_tns: Annotated[
        bool,
        Parameter(group="Assumptions for plain text prompts", help="Assume all inputs are true negatives (benign)"),
    ] = False,
    # Performance
    rps: Annotated[
        int,
        Parameter(
            group="Performance", help=RPS_HELP, validator=cyclopts.validators.Number(gte=1, lte=defaults.max_rps)
        ),
    ] = defaults.default_rps,
    max_poll_attempts: Annotated[
        int, Parameter(group="Performance", help=MAX_POLL_ATTEMPTS_HELP)
    ] = defaults.max_poll_attempts,
    fp_check_only: Annotated[
        bool, Parameter(group="Performance", help="When passing JSON file, only check for false negatives")
    ] = False,
) -> None:
    # Manual mutually exclusive check for prompt/input_file
    if (prompt is None) == (input_file is None):
        print("Error: One of the arguments --prompt or --input-file is required.")
        sys.exit(1)

    # Manual mutually exclusive check for assumptions
    if assume_tps and assume_tns:
        print("Error: Argument --assume-tps is not allowed with --assume-tns")
        sys.exit(1)

    # Determine injection helper
    def determine_injection(labels: list[str]) -> bool:
        """Heuristic to decide if this is injection or not based on labels."""
        benign_labels_set = {"benign_auto", "benign"}
        return not any(label in benign_labels_set for label in labels)  # Assume injection if not labeled as benign

    args = AppArgs(
        prompt=prompt,
        input_file=input_file,
        system_prompt=system_prompt,
        force_system_prompt=force_system_prompt,
        detectors=detectors,
        use_labels_as_detectors=use_labels_as_detectors,
        report_any_topic=report_any_topic,
        topic_threshold=topic_threshold,
        fail_fast=fail_fast,
        malicious_prompt_labels=malicious_prompt_labels,
        benign_labels=benign_labels,
        negative_labels=negative_labels,
        recipe=recipe,
        aidr_config=aidr_config,
        report_title=report_title,
        summary_report_file=summary_report_file,
        fps_out_csv=fps_out_csv,
        fns_out_csv=fns_out_csv,
        print_label_stats=print_label_stats,
        print_fps=print_fps,
        print_fns=print_fns,
        verbose=verbose,
        debug=debug,
        assume_tps=assume_tps,
        assume_tns=assume_tns,
        rps=rps,
        max_poll_attempts=max_poll_attempts,
        fp_check_only=fp_check_only,
    )

    if args.prompt:
        # If a single prompt, set rps to 1
        args.rps = 1

    aig = AIGuardManager(args)
    settings = Settings(system_prompt, recipe)
    aig_test = AIGuardTests(settings, aig, args)
    aig_test.process_all_prompts(args, aig)


if __name__ == "__main__":
    app()
