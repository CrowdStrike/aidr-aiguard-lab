# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import sys
import json
import csv
from datetime import datetime
from tzlocal import get_localzone
import threading
import time


from collections import Counter, defaultdict
from typing import List, Dict, TypedDict, Optional
from requests.models import Response
# from pydantic import BaseModel, Field

from testcase.testcase import TestCase, ExpectedDetectors
        
# from api.pangea_api import pangea_post_api, poll_request
from utils.utils import (
    apply_synonyms,
    formatted_json_str,
)
from utils.colors import (
    RED,
    DARK_RED,
    DARK_YELLOW,
    GREEN,
    DARK_GREEN,
    BRIGHT_GREEN,
    RESET,
)
from defaults import defaults


class ErrorRequestResponse:
    """Container for storing error request and response pairs."""
    def __init__(self, request_id: str, request_data: dict, response: Response):
        self.request_id = request_id  # Request ID from the API call
        self.request_data = request_data  # JSON request data
        self.response = response  # Response object


class EfficacyTracker:
    class FailedTestCase:
        def __init__(self, 
                     test: TestCase, 
                     expected_label: str = "",
                     detector_seen: str = "",
                     detector_not_seen: str = ""):
            self.test: TestCase = test
            self.expected_label: str = expected_label
            self.detector_seen: str = detector_seen
            self.detector_not_seen: str = detector_not_seen

    def __init__(
            self,
            args=None,
            keep_tp_and_tn_tests: bool = False # whether to keep copies of TP and TN test case objs for reporting later
            ):
        self.start_time = time.time()
        self.end_time = None
        self.args = args
        self.verbose = args.verbose if args else False
        self.debug = args.debug if args else False
        self.track_tp_and_tn_cases = keep_tp_and_tn_tests 
        self.use_labels_as_detectors = args.use_labels_as_detectors if args else False
        self._lock = threading.Lock()
        # Overall counts
        self.tp_count = 0
        self.fp_count = 0
        self.fn_count = 0
        self.tn_count = 0
        self.duration_sum = 0.0
        self.total_calls = 0
        # Per-detector tracking
        self.per_detector_tp = Counter()
        self.per_detector_fp = Counter()
        self.per_detector_fn = Counter()
        self.per_detector_tn = Counter()

        # Initialize label counts and stats
        self.label_counts: Counter = Counter()
        self.label_stats: defaultdict = defaultdict(lambda: {"FP": 0, "FN": 0})

        # Save collections of false positives, false negatives
        # for reporting (fps_out and fns_out).
        # These will have copies of TestCase objects that have 
        # FPs, TPs, FNs or TNs (TPs and TNs only if track_tp_and_tn_cases is True)
        # But there will be only one copy a given test case in each collection, 
        # even if it has multiple FPs, TPs, FNs or TNs.
        # So the count of each collection will be the number of test cases
        # that had FPs, TPs, FNs or TNs.  The sum of the counts of all 
        # collection should be the total number of test cases processed.
        # TODO: Check at the end that the sum of the counts of all collections
        # is equal to self.total_calls.
        self.false_positives: list[EfficacyTracker.FailedTestCase] = []
        self.true_positives: list[EfficacyTracker.FailedTestCase] = []
        self.false_negatives: list[EfficacyTracker.FailedTestCase] = []
        self.true_negatives: list[EfficacyTracker.FailedTestCase] = []

        # Initialize error tracking
        # TODO: Modify AIGuardManager to track these here.
        self.error_responses: list[ErrorRequestResponse] = []
        self.errors: Counter = Counter()
        self.blocked = 0

    def add_false_positive(
        self,
        test: TestCase,
        detector_seen: str,
        expected_label: str
    ):
        """
        Add a test case to the false positives collection.
        This is used to track test cases where no detection was expected 
        for the given detector, but detection was seen.
        """
        with self._lock:
            duplicate = any(
                fp.test == test and fp.detector_seen == detector_seen
                for fp in self.false_positives
            )
            if not duplicate:
                self.false_positives.append(
                    EfficacyTracker.FailedTestCase(
                        test,
                        expected_label=expected_label,
                        detector_seen=detector_seen
                    )
                )
                # Increment counts only for a truly new FP
                self.fp_count += 1
                self.per_detector_fp[detector_seen] += 1
                self.label_stats[detector_seen]["FP"] += 1

        if self.verbose:
            index = test.index if hasattr(test, 'index') else "unknown"
            print(f"{DARK_RED}Test:{index}:FP: expected_label '{expected_label}' but detected '{detector_seen}'")
            print(
                f"\t{DARK_YELLOW}Messages:\n"
                f"{DARK_RED}{formatted_json_str(test.messages[:3])}{RESET}"
            )

    def add_true_negative(
        self,
        test: TestCase,
        detector_not_seen: str,
        expected_label: str = "benign"
    ):
        """
        TODO: MAY NOT WANT TO DO THIS - COULD BE NOISY (at least not keep every test case)
        Add a test case to the true positives collection.
        This is used to track test cases where a detection was not expected
        for expected_label and it was not seen.
        TODO: Get rid of FailedTestCase, since we've added detector_not_seen, etc. to the base TestCase class.
        """
        with self._lock:
            if test not in self.true_negatives:
                if self.track_tp_and_tn_cases:
                    self.true_negatives.append(
                        EfficacyTracker.FailedTestCase(
                            test,
                            expected_label=expected_label,
                            detector_not_seen=detector_not_seen
                        )
                    )
            self.tn_count += 1
            self.per_detector_tn[detector_not_seen] += 1

        if self.debug:
            print(f"{DARK_GREEN}TN: expected_label '{expected_label}' detected '{detector_not_seen}'")
            print(
                f"\t{DARK_YELLOW}Messages:\n"
                f"{DARK_GREEN}{formatted_json_str(test.messages[:3])}{RESET}"
            )

    def add_true_positive(
        self,
        test: TestCase,
        detector_seen: str,
        expected_label: str
    ):
        """
        Add a test case to the true positives collection.
        This is used to track test cases where a detection was expected
        for detector_seen given expected_label, and it was seen.
        """
        with self._lock:
            if test not in self.true_positives:
                if self.track_tp_and_tn_cases:
                    self.true_positives.append(
                        EfficacyTracker.FailedTestCase(
                            test,
                            expected_label=expected_label,
                            detector_seen=detector_seen
                        )
                    )
            self.tp_count += 1
            self.per_detector_tp[detector_seen] += 1

        if self.debug:
            print(f"{DARK_GREEN}TP: expected_label '{expected_label}' detected '{detector_seen}'")
            print(
                f"\t{DARK_YELLOW}Messages:\n"
                f"{DARK_GREEN}{formatted_json_str(test.messages[:3])}{RESET}"
            )

    def add_false_negative(
            self,
            test: TestCase,
            detector_not_seen: str,
            expected_label: str
    ):
        """
        Add a test case to the false negatives collection.
        This is used to track test cases where a detection was expected for
        the given detector but was not seen.
        """
        with self._lock:
            if not any(fn.test == test and fn.detector_not_seen == detector_not_seen for fn in self.false_negatives):
                self.false_negatives.append(
                    EfficacyTracker.FailedTestCase(
                        test,
                        expected_label=expected_label,
                        detector_not_seen=detector_not_seen)
                )
            self.fn_count += 1
            self.per_detector_fn[detector_not_seen] += 1
            self.label_stats[detector_not_seen]["FN"] += 1

        if self.verbose:
            index = test.index if hasattr(test, 'index') else "unknown"
            print(f"{DARK_RED}Test:{index}:FN: expected detection: '{detector_not_seen}' for expected_label:'{expected_label}'")
            print(
                f"\t{DARK_YELLOW}Messages:\n"
                f"{DARK_RED}{formatted_json_str(test.messages[:3])}{RESET}"
            )

    def update(
            self,
            test: TestCase,
            expected_labels: List[str],
            detected_detectors_labels: List[str],
            benign_labels: List[str] = defaults.benign_labels,
            malicious_prompt_labels: List[str] = defaults.malicious_prompt_labels,
            negative_labels: List[str] | None = None,
            ):
        """
        Update efficacy statistics by comparing expected and actual detector results.
        Return FP_DETECTED, FN_DETECTED, FP_NAMES, FN_NAMES

        (ignore block vs report, and only apply malicious_prompt_labels and benign_labels to malicious-prompt detector):
        Label on a test case means a detector or topic of that name is expected as a TP
            Consider any label in malicious_prompt_labels to be synonyms of “malicious-prompt”
                Replace any test.labels that match something in the malicious_prompt_labels with “malicious-prompt”
                Remove any duplicates from test.labels
            Failure to see a detection matching that label is a FN
            Seeing a detection that doesn’t match a label on the test case is a FP

        Logic:
            detected_detectors_labels = AIG(test)
            Expected_labels = test.labels
            Expected_labels = apply_synonyms(test.labels, malicious_prompt_labels)
            For each expected in expected_labels:
                If expected in detected_detectors_labels:
                    TP(expected)
                Else:
                    FN(expected)
            For each detected in detected_detectors_labels:
                If not detected in expected_labels:
                    FP(detected)

        How do benign_labels come in?
            They should have been removed if seen - benign means no detection expected.

        """
       
        # Default negative_labels if none passed
        if negative_labels is None:
            negative_labels = [f"{defaults.not_topic_prefix}*"]  # default pattern

        # Allow single-string inputs by wrapping into a list
        if isinstance(expected_labels, str):
            expected_labels = [expected_labels]

        if isinstance(detected_detectors_labels, str):
            detected_detectors_labels = [detected_detectors_labels]

        # Normalize inputs to lists of strings
        expected_labels = expected_labels or []
        detected_detectors_labels = detected_detectors_labels or []
        expected_labels = [str(label) for label in expected_labels]
        detected_detectors_labels = [
            str(det) for det in detected_detectors_labels
        ]

        # Extract expected labels directly from the test case label field.
        # Supports multiple formats:
        # - If label is a dict: handle 'not-topic' and 'not-nalicious-prompt' cases with special logic.
        # - If label is a list: treat each list item as a label.
        # - If label is a simple string: treat it as a single label.
        # The original_labels are kept for negative label processing before canonicalization.
        expected_labels = []
        raw_label = getattr(test, "label", None)
        if isinstance(raw_label, dict):
            kind = raw_label.get("kind", "").strip().lower()
            tag = raw_label.get("tag", "").strip().lower()

            if kind == "not-topic" and tag:
                expected_labels.append(f"not-topic:{tag}")
            elif kind == "notmaliciousprompt" and tag:
                expected_labels.append(kind)
                expected_labels.append(tag)
            else:
                if kind:
                    expected_labels.append(kind)
                if tag:
                    expected_labels.append(tag)
        elif isinstance(raw_label, list):
            expected_labels.extend(str(lbl).strip().lower() for lbl in raw_label)
        elif isinstance(raw_label, str):
            expected_labels.append(raw_label.strip().lower())

        original_labels = expected_labels.copy()

        # Canonicalize expected_labels (strip 'topic:' if present)
        def _canon(label: str) -> str:
            if label.startswith(defaults.topic_prefix):
                return label.split(defaults.topic_prefix, 1)[1]  # drop prefix
            return label
        expected_labels = [_canon(lbl) for lbl in expected_labels]

        # Canonicalize detected labels as well (strip 'topic:' if present)
        original_detected_labels = detected_detectors_labels.copy()  # keep for debug / reporting
        detected_detectors_labels = [_canon(lbl) for lbl in detected_detectors_labels]

        # Build negative_label_map from original_labels (before canonicalization)
        negative_label_map: dict[str, str] = {}
        for lbl in original_labels:
            if isinstance(lbl, str) and lbl.startswith("not-topic:"):
                detector_name = _canon(lbl.replace("not-", "", 1))
                negative_label_map[detector_name] = lbl

        if self.debug:
            print(f"[DEBUG] original_labels        = {original_labels}")
            print(f"[DEBUG] negative_label_map     = {negative_label_map}")
            print(f"[DEBUG] detected_detectors_lbl = {detected_detectors_labels}")

        # Remove negative labels from expected_labels
        expected_labels = [
            lbl for lbl in expected_labels
            if not (isinstance(lbl, str) and lbl.startswith("not-topic:"))
        ]

        # Supplement expected_labels with positive topic labels from original_labels if missing
        for lbl in original_labels:
            if isinstance(lbl, str) and not lbl.startswith("not-topic:"):
                canon_lbl = _canon(lbl)
                if canon_lbl and canon_lbl not in expected_labels:
                    expected_labels.append(canon_lbl)

        # Special handling for explicit benign and NotMaliciousPrompt test cases
        explicit_benign = False
        explicit_not_mal_prompt = False
        all_labels = [str(lbl) for lbl in (expected_labels + original_labels)]
        for lbl in all_labels:
            if lbl in benign_labels or lbl.lower() == "benign":
                explicit_benign = True
            if lbl.lower() in ["notmaliciousprompt", "not-malicious-prompt"]:
                explicit_not_mal_prompt = True
        if explicit_not_mal_prompt:
            if self.debug:
                print(f"{DARK_YELLOW}Detected NotMaliciousPrompt case. Only 'malicious-prompt' not expected.{RESET}")
                print(f"expected_labels={expected_labels}")
                print(f"original_labels={original_labels}")
                print(f"detected_detectors_labels={detected_detectors_labels}")

            # Explicitly add 'malicious-prompt' to negative_label_map
            negative_label_map["malicious-prompt"] = "not-malicious-prompt"

            if "malicious-prompt" in detected_detectors_labels:
                self.add_false_positive(
                    test,
                    expected_label="malicious-prompt",
                    detector_seen="malicious-prompt"
                )
            else:
                self.add_true_negative(
                    test,
                    expected_label="malicious-prompt",
                    detector_not_seen="malicious-prompt"
                )
            # Remove helper labels to prevent double-counting downstream
            expected_labels = [
                lbl for lbl in expected_labels
                if lbl not in ("malicious-prompt", "not-malicious-prompt")
            ]
            negative_label_map.pop("malicious-prompt", None)
            negative_label_map.pop("not-malicious-prompt", None)
        elif explicit_benign:
            if self.debug:
                print(f"{DARK_YELLOW}Detected explicit benign test case. No detections expected.{RESET}")
                print(f"expected_labels={expected_labels}")
                print(f"original_labels={original_labels}")
                print(f"detected_detectors_labels={detected_detectors_labels}")
            for detected in detected_detectors_labels:
                self.add_false_positive(
                    test,
                    expected_label="benign",
                    detector_seen=detected
                )
            expected_labels.clear()
            negative_label_map.clear()

        # self.total_calls += 1 # This is handled in AIGuardManager

        # Initialize return values
        fp_detected = False
        fn_detected = False
        tp_detected = False
        tn_detected = False
        fp_names: list[str] = []
        fn_names: list[str] = []

        # Track FP, FN, TP, TN conditions for this test case
        found_fp = set()
        found_fn = set()
        found_tp = set()
        found_tn = set()

        # Apply synonyms to expected_labels for "malicious-prompt"
        expected_labels += apply_synonyms(expected_labels, malicious_prompt_labels, "malicious-prompt")
        expected_labels += apply_synonyms(expected_labels, benign_labels, "benign")
        expected_labels = list(dict.fromkeys(expected_labels))  # dedupe, order‑stable
        if "benign" in expected_labels:
            expected_labels.remove("benign")  # Remove "benign" from expected_labels

        # Update label_counts
        if test and test.label:
            with self._lock:
                for label in test.label:
                    self.label_counts[label] += 1

        if self.debug:
            print(f"\n\nDetected detectors labels (canonical): {detected_detectors_labels}")
            print(f"Detected detectors labels (raw)      : {original_detected_labels}")
            print(f"Expected labels: {expected_labels}")

        for expected in expected_labels:
            if expected in detected_detectors_labels:
                # If the expected label is in the detected labels, it's a True Positive
                if self.debug:
                    print(f"{DARK_YELLOW}Checking for expected label '{expected}' in detected_detectors_labels...{RESET}")
                    print(f"{DARK_GREEN}TP: Expected label '{expected}' detected in {detected_detectors_labels}{RESET}")

                tp_detected = True
                found_tp.add(expected)

                self.add_true_positive(
                    test,
                    expected_label=expected,
                    detector_seen=expected
                )
            else:
                # If the expected label is not in the detected labels, it's a False Negative
                if self.debug:
                    print(f"{DARK_YELLOW}Checking for expected label '{expected}' in detected_detectors_labels...{RESET}")
                    print(f"{DARK_YELLOW}FN: Expected label '{expected}' not detected in {detected_detectors_labels}{RESET}")

                fn_detected = True
                found_fn.add(expected)

                self.add_false_negative(
                    test,
                    detector_not_seen=expected,
                    expected_label=expected
                )

        # --------------------------------------------------------------
        # Any detection that does not match an expected label is a False Positive.
        # --------------------------------------------------------------  
        for detected in detected_detectors_labels:
            if detected not in expected_labels:
                fp_detected = True
                found_fp.add(detected)
                self.add_false_positive(
                    test,
                    expected_label=f"{defaults.not_topic_prefix}{detected}",
                    detector_seen=detected
                )
            # else: would have already been counted as a TP above

        # ------------------------------
        # Evaluate negative label cases
        # ------------------------------
        for neg_detector, neg_label in negative_label_map.items():
            if neg_detector in detected_detectors_labels:
                # Detector fired when it should not → FP
                fp_detected = True
                found_fp.add(neg_detector)
                self.add_false_positive(
                    test,
                    expected_label=neg_label,
                    detector_seen=neg_detector,
                )
            else:
                # Correctly silent → TN
                tn_detected = True
                found_tn.add(neg_detector)
                self.add_true_negative(
                    test,
                    expected_label=neg_label,
                    detector_not_seen=neg_detector,
                )

        # No fallback creation of TNs for "benign/topic" when not referenced.
        if not expected_labels and not negative_label_map:
            # Nothing was expected for this test‑case.
            unexpected = next(iter(detected_detectors_labels), None)
            if unexpected == "malicious-prompt":
                # Only malicious‑prompt counts as a FP in this benign scenario.
                if self.debug:
                    print(
                        f"{DARK_YELLOW}Benign case: unexpected 'malicious-prompt' "
                        f"– counting 1 FP for this test‑case.{RESET}"
                    )
                fp_detected = True
                found_fp.add(unexpected)
                self.add_false_positive(
                    test,
                    expected_label="benign",
                    detector_seen=unexpected
                )
        # else: expected_labels not empty  →  extras are ignored

        # ---------------------------------------------------------
        # Ignore detectors that are not referenced (positively or
        # negatively) in the test‑case labels. No fallback TNs.
        # ---------------------------------------------------------
        for det in detected_detectors_labels:
            if det in expected_labels:      # already handled as TP
                continue
            if det in negative_label_map:   # handled above
                continue
            # If we reach here:
            #   * det is NOT expected
            #   * det has NO explicit negative label
            # → therefore IGNORE it (neither FP nor TN/FN)

        # Update case-level counts: record both false positives and false
        # negatives if present
        if found_fp:
            fp_detected = True
            # Only add each (test, detector) once, so no duplication.
            fp_names.extend(found_fp)
        if found_fn:
            fn_detected = True
            fn_names.extend(found_fn)

        # ---------------------------------------------------------
        # Make sure every detector that appears ONLY in negative
        # labels is represented, so it shows up in per‑detector TNs.
        # ---------------------------------------------------------
        for neg_detector in negative_label_map.keys():
            if neg_detector not in self.per_detector_tp \
               and neg_detector not in self.per_detector_fp \
               and neg_detector not in self.per_detector_fn \
               and neg_detector not in self.per_detector_tn:
                self.per_detector_tn[neg_detector] = 0

        # Make sure benign‑fallback counts have a TN bucket for malicious‑prompt
        if "malicious-prompt" not in self.per_detector_tn \
           and "malicious-prompt" not in self.per_detector_tp \
           and "malicious-prompt" not in self.per_detector_fp \
           and "malicious-prompt" not in self.per_detector_fn:
            self.per_detector_tn["malicious-prompt"] = 0

        # ---------------------------------------------------------
        # Print final debug state before fallback
        # ---------------------------------------------------------
        if self.debug:
            print(f"[DEBUG] Final expected_labels: {expected_labels}")
            print(f"[DEBUG] Final negative_label_map: {negative_label_map}")

        # ---------------------------------------------------------
        # Final fallback to guarantee every test counts for TP or TN
        # ---------------------------------------------------------
        if not any([fp_detected, fn_detected, tp_detected, tn_detected]):
            # No bucket was incremented. Guarantee a count.
            if expected_labels and detected_detectors_labels:
                tp_detected = True
                self.add_true_positive(
                    test,
                    detector_seen="benign",
                    expected_label="benign"
                )
                if self.debug:
                    print(f"{DARK_YELLOW}Fallback: counted as TP{RESET}")
            else:
                tn_detected = True
                # Count a TN under the *malicious‑prompt* detector,
                # since the benign test implicitly expects it to stay silent.
                self.add_true_negative(
                    test,
                    detector_not_seen="malicious-prompt",
                    expected_label="benign"
                )
                if self.debug:
                    print(f"{DARK_YELLOW}Fallback: counted as TN for malicious-prompt{RESET}")

        return (fp_detected, fn_detected, fp_names, fn_names)

    class MetricsDict(TypedDict, total=False):
        accuracy: float
        precision: float
        recall: float
        f1_score: float
        specificity: float
        fp_rate: float
        fn_rate: float

        tp_count: int
        tn_count: int
        fp_count: int
        fn_count: int
        total_count: int

        # Optional fields for overall metrics
        avg_duration: float
        total_calls: int    # total number of calls made to AI Guard
        fp_saved_test_count: int  # saved test cases with false positives
        fn_saved_test_count: int  # saved test cases with false negatives
        tp_saved_test_count: int  # saved test cases with true positives (only if track_tp_and_tn_cases is True)
        tn_saved_test_count: int  # saved test cases with true negatives (only if track_tp_and_tn_cases is True)
        total_saved_test_count: int  # total saved test cases non-zero efficacy
        tp_detector_summary: str  # summary of per-detector TP counts
        fp_detector_summary: str  # summary of per-detector FP counts
        fn_detector_summary: str  # summary of per-detector FN counts
        tn_detector_summary: str  # summary of per-detector TN counts



    def calculate_metrics(self) -> Dict[str, "EfficacyTracker.MetricsDict"]:
        """
        Calculate and return various metrics based on the current counts.
        Returns a map of detector names to their metrics.
        metrics["name"] = detector_metrics
        Names can be "overall", <detector_name> or <topic_name>, or <label_name>
        """
        all_metrics: dict[str, MetricsDict] = {}

        # TODO: Check at the end that the sum of the counts of all collections
        # is equal to self.total_calls.
        fp_test_count = len(self.false_positives)
        fn_test_count = len(self.false_negatives)
        tp_test_count = len(self.true_positives)
        tn_test_count = len(self.true_negatives)
        total_test_count = (fp_test_count + fn_test_count + tp_test_count + tn_test_count)

        tp = self.tp_count
        fp = self.fp_count
        fn = self.fn_count
        tn = self.tn_count
        total = tp + fp + fn + tn

        fp_rate = fp / (fp + tn) if (fp + tn) else 0
        fn_rate = fn / (tp + fn) if (tp + fn) else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0
        f1 = (
            2 * precision * recall / (precision + recall) if (precision + recall) else 0
        )
        accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else 0
        specificity = tn / (tn + fp) if (tn + fp) else 0
        # TODO: Ensure that the overall_metrics are only calculated against per-test case metrics,
        # not the overall counts.
        # Each test case can have multiple labels and there can be tps, tns, fps, fns for each label.
        # So we need to calculate the metrics for each label, detector, and topic separately.
        overall_metrics: EfficacyTracker.MetricsDict = {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "specificity": specificity,
            "fp_rate": fp_rate,
            "fn_rate": fn_rate,

            "total_count": total,
            "tp_count": self.tp_count,
            "tn_count": self.tn_count,
            "fp_count": self.fp_count,
            "fn_count": self.fn_count,

            "avg_duration": self.duration_sum / self.total_calls if self.total_calls else 0.0,
            "total_calls": self.total_calls,
            "total_saved_test_count": total_test_count,
            "fp_saved_test_count": fp_test_count,
            "fn_saved_test_count": fn_test_count,
            "tp_saved_test_count": tp_test_count,
            "tn_saved_test_count": tn_test_count,
            "tp_detector_summary": f"{dict(self.per_detector_tp)}",
            "fp_detector_summary": f"{dict(self.per_detector_fp)}",
            "fn_detector_summary": f"{dict(self.per_detector_fn)}",
            "tn_detector_summary": f"{dict(self.per_detector_tn)}",
        }
        all_metrics["overall"] = overall_metrics

        # Per-detector metrics
        all_detectors = (
            set(self.per_detector_tp)
            | set(self.per_detector_fp)
            | set(self.per_detector_fn)
            | set(self.per_detector_tn)
        )
        for detector in all_detectors:
            tp = self.per_detector_tp[detector]
            fp = self.per_detector_fp[detector]
            fn = self.per_detector_fn[detector]
            tn = self.per_detector_tn[detector]
            total = tp + fp + fn + tn
            fp_rate = fp / (fp + tn) if (fp + tn) else 0
            fn_rate = fn / (tp + fn) if (tp + fn) else 0
            precision = tp / (tp + fp) if (tp + fp) else 0
            recall = tp / (tp + fn) if (tp + fn) else 0
            f1 = (
                2 * precision * recall / (precision + recall) if (precision + recall) else 0
            )
            accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else 0
            specificity = tn / (tn + fp) if (tn + fp) else 0
            det_metrics: EfficacyTracker.MetricsDict = {
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "specificity": specificity,
                "fp_rate": fp_rate,
                "fn_rate": fn_rate,

                "total_count": total,
                "tp_count": tp,
                "tn_count": tn,
                "fp_count": fp,
                "fn_count": fn,
            }
            all_metrics[detector] = det_metrics

        return all_metrics

    def print_errors(self):
        if len(self.errors) == 0:
            return
        if self.verbose:
            print(f"\n--- {DARK_RED}Errors encountered during AI Guard calls:{RESET} --")
            for error_pair in self.error_responses:
                try:
                    print(f"{DARK_YELLOW}Request ID:{RESET} {error_pair.request_id}")
                    print(f"{DARK_YELLOW}Request Data:{RESET}")
                    formatted_json_request = json.dumps(error_pair.request_data, indent=4)
                    print(f"{formatted_json_request}")
                    print(f"{DARK_YELLOW}Response:{RESET}")
                    formatted_json_error = json.dumps(error_pair.response.json(), indent=4)
                    print(f"{formatted_json_error}")
                    print("-" * 50)
                except Exception as e:
                    print(f"Error in print_errors: {e}")
                    print(f"Error response: {error_pair}")
        # TODO: Make this happen as errors are added to the collection
        #       and flush to disk so callers can monitor errors in real-time.
        if self.args.summary_report_file:
            error_report_file = self.args.summary_report_file + ".errors.txt"
            with open(error_report_file, "w") as f:
                f.write("\nErrors:\n")
                for error_pair in self.error_responses:
                    try:
                        f.write(f"Request ID: {error_pair.request_id}\n")
                        f.write("Request Data:\n")
                        formatted_json_request = json.dumps(error_pair.request_data, indent=4)
                        f.write(f"{formatted_json_request}\n")
                        f.write("Response:\n")
                        formatted_json_error = json.dumps(error_pair.response.json(), indent=4)
                        f.write(f"{formatted_json_error}\n")
                        f.write("-" * 50 + "\n")
                    except Exception as e:
                        f.write(f"Error in print_errors: {e}\n")
                        f.write(f"Error response: {error_pair}\n")


    def print_stats(self, enabled_detectors: List[str] = None):
        """ Print a summary of the efficacy statistics.
            Print default reports, and any requested by the user.
            summary_report_file is the file to write the summary report to.
            fps_out_csv is the file to write false positives to.
            fns_out_csv is the file to write false negatives to.
            TODO: Add fps_out and fns_out that derive the output file type from the file extension.
            TODO: Add create_summary_csv() support as is done in prompt-lab.
        """
        def _print_all_stats(writeln):
            # Strip out helper/pseudo‑detector labels that should never get their own stats section
            if "benign" in enabled_detectors:
                enabled_detectors.remove("benign")
            if "" in enabled_detectors:
                enabled_detectors.remove("")
            if "not-malicious-prompt" in enabled_detectors:
                enabled_detectors.remove("not-malicious-prompt")

            metrics = self.calculate_metrics()
            writeln(f"\n{BRIGHT_GREEN}AIGuard Efficacy Report{RESET}")
            if self.args and self.args.report_title:
                writeln(f"{self.args.report_title}")

            local_tz = get_localzone()
            local_time = datetime.now(local_tz)
            formatted_time = local_time.strftime("%Y-%m-%d %H:%M:%S %Z (UTC%z)")
            writeln(f"Report generated at: {formatted_time}")
            writeln(f"CMD: {' '.join(sys.argv)}")
            if self.args and self.args.input_file:
                writeln(f"Input dataset: {self.args.input_file}")
            writeln(f"Service: {defaults.ai_guard_service}")
            writeln(f"Total Calls: {self.total_calls}")
            writeln(f"Requests per second: {self.args.rps}")
            writeln(f"Average duration: {metrics['overall']['avg_duration']:.4f} seconds")
            writeln(f"Total duration: {self.end_time - self.start_time:.2f} seconds")
            writeln(f"\n{RED}Errors: {self.errors}{RESET}")

            for detector, det_metrics in metrics.items():
                # Filter unused detectors
                if detector not in enabled_detectors and detector != "overall":
                    ## TODO: This isn't the complete check -
                    ## Need to account for detectors that were enabled via overrides or test cases
                    continue

                if detector == "overall":
                   writeln(f"\n--{GREEN}Overall Counts:{RESET}--")
                else:
                    writeln(f"\n--{GREEN}Detector: {detector}{RESET}--")

                # Summarize detectors with zero counts
                if det_metrics['total_count'] == 0:
                    writeln(f"{DARK_YELLOW}No non-zero results for this detector.{RESET}")
                    continue

                writeln(f"{DARK_GREEN}True Positives: {det_metrics['tp_count']}{RESET}")
                writeln(f"{DARK_GREEN}True Negatives: {det_metrics['tn_count']}{RESET}")
                writeln(f"{DARK_RED}False Positives: {det_metrics['fp_count']}{RESET}")
                writeln(f"{DARK_RED}False Negatives: {det_metrics['fn_count']}{RESET}")
                writeln(f"\nAccuracy: {DARK_GREEN}{det_metrics['accuracy']:.4f}{RESET}")
                writeln(f"Precision: {DARK_GREEN}{det_metrics['precision']:.4f}{RESET}")
                writeln(f"Recall: {DARK_GREEN}{det_metrics['recall']:.4f}{RESET}")
                writeln(f"F1 Score: {DARK_GREEN}{det_metrics['f1_score']:.4f}{RESET}")
                writeln(f"Specificity: {DARK_GREEN}{det_metrics['specificity']:.4f}{RESET}")
                writeln(f"False Positive Rate: {DARK_RED}{det_metrics['fp_rate']:.4f}{RESET}")
                writeln(f"False Negative Rate: {DARK_RED}{det_metrics['fn_rate']:.4f}{RESET}")
                if detector == "overall":
                    writeln(f"\n{GREEN}-- Info on Test Cases Saved for Reporting {RESET}--")
                    writeln(f"track_tp_and_tn_cases: {self.track_tp_and_tn_cases}")
                    writeln(f"Total Test Cases Saved: {det_metrics['total_saved_test_count']}")
                    if det_metrics['total_saved_test_count'] == 0:
                        writeln(f"{DARK_YELLOW}No test cases saved.{RESET}")
                    else:
                        writeln(f"{DARK_RED}Saved Test Cases with FPs: {det_metrics['fp_saved_test_count']}{RESET}")
                        writeln(f"{DARK_RED}Saved Test Cases with FNs: {det_metrics['fn_saved_test_count']}{RESET}")
                        writeln(f"{DARK_GREEN}Saved Test Cases with TPs: {det_metrics['tp_saved_test_count']}{RESET}")
                        writeln(f"{DARK_GREEN}Saved Test Cases with TNs: {det_metrics['tn_saved_test_count']}{RESET}")
                    ## TODO: Don't output these if they are empty
                    writeln(f"{DARK_RED}Summary of Per-detector FPs: {det_metrics['fp_detector_summary']}{RESET}")
                    writeln(f"{DARK_RED}Summary of Per-detector FNs: {det_metrics['fn_detector_summary']}{RESET}")
                    writeln(f"\n{DARK_GREEN}Summary of Per-detector TPs: {det_metrics['tp_detector_summary']}{RESET}")
                    writeln(f"{DARK_GREEN}Summary of Per-detector TNs: {det_metrics['tn_detector_summary']}{RESET}")
            if self.args and self.args.print_label_stats:
                self._print_label_stats(writeln=writeln)
            if self.args and self.args.print_fps:
                writeln(f"\n--{GREEN}False Positives:{RESET}--")
                if not self.false_positives:
                    writeln(f"{DARK_YELLOW}No false positives recorded.{RESET}")
                else:
                    for fp_case in self.false_positives:
                        writeln(f"{DARK_RED}Test Case: {fp_case.test.index}, Expected Label: {fp_case.expected_label}, Detected: {fp_case.detector_seen}")
                        writeln(f"\tMessages: {formatted_json_str(fp_case.test.messages[:3])}")
            if self.args and self.args.print_fns:
                writeln(f"\n--{GREEN}False Negatives:{RESET}--")
                if not self.false_negatives:
                    writeln(f"{DARK_YELLOW}No false negatives recorded.{RESET}")
                else:
                    for fn_case in self.false_negatives:
                        writeln(f"{DARK_RED}Test Case: {fn_case.test.index}, Expected Label: {fn_case.expected_label}, Not Detected: {fn_case.detector_not_seen}")
                        writeln(f"\tMessages: {formatted_json_str(fn_case.test.messages[:3])}")

        """ print_stats() body here"""
        self.end_time = time.time()
        if self.args and self.args.summary_report_file:
            with open(self.args.summary_report_file, "w") as f:
                def writeln(line: str = ""):
                    print(line)
                    f.write(line + "\n")
                _print_all_stats(writeln)
        else:
            def writeln(line: str = ""):
                print(line)
            _print_all_stats(writeln)
        # print fps_out_csv and fns_out_csv if specified
        if self.args and self.args.fps_out_csv:
            fps_out_csv = self.args.fps_out_csv
            EfficacyTracker.print_cases_csv(
                fps_out_csv,
                positive=True,  # True for false positives
                cases=self.false_positives
            )
        if self.args and self.args.fns_out_csv:
            fns_out_csv = self.args.fns_out_csv
            EfficacyTracker.print_cases_csv(
                fns_out_csv,
                positive=False,  # False for false negatives
                cases=self.false_negatives
            )
    @staticmethod
    def print_cases_csv(out_csv: str, positive: bool, cases: list["EfficacyTracker.FailedTestCase"]):
        """
        Print test cases (false positives, false negatives, etc.) to a CSV file.

        Args:
            out_csv (str): Output CSV file path.
            cases (list): List of EfficacyTracker.FailedTestCase objects.
        """
        if not out_csv.endswith(".csv"):
            out_csv += ".csv"
        try:
            with open(out_csv, mode="w", newline="", encoding="utf-8") as csvfile:
                csvwriter = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
                csvwriter.writerow(
                    [
                        "Test Case Index",
                        "Test Messages",
                        "System Prompt",
                        "Expected Label",
                        "Test Case Labels",
                        "FP Detector" if positive else "FN Detector",
                    ]
                )
                for case in cases:
                    messages = (
                        case.test.messages
                        if case.test.messages
                        else [{"role": "user", "content": "No User Message"}]
                    )
                    # Join all user messages for context, sanitize to remove newlines and carriage returns
                    test_case_messages = " | ".join(
                        msg["content"].replace("\n", " ").replace("\r", " ")
                        for msg in messages if msg.get("role") == "user"
                    ) or "No Messages"
                    test_case_index = (
                        case.test.index if getattr(case.test, "index", None) is not None else "N/A"
                    )
                    expected_labels = (
                        ",".join(case.expected_label)
                        if isinstance(case.expected_label, list)
                        else case.expected_label
                    )
                    test_case_labels = (
                        ",".join(case.test.label)
                        if isinstance(case.test.label, list)
                        else case.test.label
                    )
                    system_prompt = case.test.get_system_message()
                    system_prompt = system_prompt.replace("\n", " ").replace("\r", " ")

                    # Use detector_seen if present, else detector_not_seen; always a string.
                    detector_field = getattr(case, "detector_seen" if positive else "detector_not_seen", None)
                    detected_detectors = detector_field
                    csvwriter.writerow(
                        [
                            test_case_index,
                            test_case_messages,
                            system_prompt,
                            expected_labels,
                            test_case_labels,
                            detected_detectors,
                        ]
                    )
            if positive:
                print(f"{DARK_GREEN}FPs written to {out_csv}{RESET}")
            else:
                print(f"{DARK_GREEN}FNs written to {out_csv}{RESET}")
        except Exception as e:
            print(f"{DARK_RED}Error writing to CSV: {e}{RESET}")
            return None
        return out_csv

    def print_fns_csv(self, fns_out_csv: str):
        """ Print false negatives to a CSV file.
        """
        if not fns_out_csv.endswith(".csv"):
            fns_out_csv += ".csv"
        print(f"Writing false negatives to {fns_out_csv}")
        with open(fns_out_csv, "w") as f:
            f.write("Test Case Index,Expected Label,Not Detected Detector\n")
            for fn_case in self.false_negatives:
                f.write(f"{fn_case.test.index},{fn_case.expected_label},{fn_case.detector_not_seen}\n")
        print(f"{DARK_GREEN}False negatives written to {fns_out_csv}{RESET}")

    def _print_label_stats(self, writeln):
        """ Print label-wise false positives and false negatives.
        """
        writeln(f"\n--{GREEN}Label-wise False Positives and False Negatives:{RESET}--")
        if not self.label_stats:
            writeln(f"{DARK_YELLOW}No label stats available.{RESET}")
            return
        writeln(f"Label Stats: {dict(self.label_stats)}")
        for label, stats in self.label_stats.items():
            fp = stats.get("FP", 0)
            fn = stats.get("FN", 0)
            writeln(f"\tLabel: {label}, False Positives: {fp}, False Negatives: {fn}")


    @staticmethod
    def is_subset(expected: dict, actual: dict):
        """
        Recursively checks if expected is a subset of actual.
        - For dicts: all keys/values in expected must be present in actual (recursively).
        - For lists: every item in expected must be present in actual (order doesn't matter).
        - For other types: must be equal.
        Ignores differences if the key name is "confidence".
        Returns (True, None) if subset, else (False, (expected, actual)) for the first mismatch.
        """
        if expected is None:
            return True, None  # Nothing expected, always a subset
        if actual is None:
            return False, (expected, actual)  # Expected something, got nothing

        if isinstance(expected, dict) and isinstance(actual, dict):
            for key, value in expected.items():
                if key == "confidence":
                    continue  # Ignore confidence differences
                if key not in actual:
                    return False, (f"Missing key '{key}'", expected, actual)
                is_sub, mismatch = EfficacyTracker.is_subset(value, actual[key])
                if not is_sub:
                    return False, mismatch
            return True, None
        elif isinstance(expected, list) and isinstance(actual, list):
            actual_copy = list(actual)
            for exp_item in expected:
                found = False
                for idx, act_item in enumerate(actual_copy):
                    is_sub, mismatch = EfficacyTracker.is_subset(exp_item, act_item)
                    if is_sub:
                        found = True
                        del actual_copy[idx]
                        break
                if not found:
                    return False, (exp_item, actual)
            return True, None
        else:
            if expected != actual:
                return False, (expected, actual)
            return True, None

