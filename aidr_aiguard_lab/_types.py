from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from aidr_aiguard_lab.defaults import defaults


class AppArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt: str | None = None
    input_file: str | None = None
    system_prompt: str | None = None
    force_system_prompt: bool = False
    detectors: str = defaults.default_detectors_str
    use_labels_as_detectors: bool = False
    report_any_topic: bool = False
    topic_threshold: float = defaults.topic_threshold
    fail_fast: bool = False
    malicious_prompt_labels: str = defaults.malicious_prompt_labels_str
    benign_labels: str = defaults.benign_labels_str
    negative_labels: str = "not-topic:*"
    recipe: str = defaults.default_recipe
    aidr_config: str | None = None
    report_title: str | None = None
    summary_report_file: str | None = None
    fps_out_csv: str | None = None
    fns_out_csv: str | None = None
    print_label_stats: bool = False
    print_fps: bool = False
    print_fns: bool = False
    verbose: bool = False
    debug: bool = False
    assume_tps: bool = False
    assume_tns: bool = False
    rps: int = defaults.default_rps
    max_poll_attempts: int = defaults.max_poll_attempts
    fp_check_only: bool = False
