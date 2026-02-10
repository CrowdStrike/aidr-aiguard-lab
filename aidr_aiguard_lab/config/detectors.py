from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass
class CodeDetection:
    disabled: bool | None = None
    action: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> CodeDetection:
        if not data:
            return cls()
        return cls(
            disabled=data.get("disabled"),
            action=data.get("action"),
        )


@dataclass
class Competitors:
    disabled: bool | None = None
    action: str | None = None
    competitors: list[str] | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> Competitors:
        if not data:
            return cls()
        return cls(**data)


@dataclass
class LanguageDetection:
    disabled: bool | None = None
    action: str | None = None
    languages: list[str] | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> LanguageDetection:
        if not data:
            return cls()
        return cls(**data)


@dataclass
class MaliciousEntity:
    disabled: bool | None = None
    url: str | None = None
    ip_address: str | None = None
    domain: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> MaliciousEntity:
        if not data:
            return cls()
        return cls(**data)


@dataclass
class PIIEntity:
    disabled: bool | None = None
    email_address: str | None = None
    nrp: str | None = None
    location: str | None = None
    person: str | None = None
    phone_number: str | None = None
    date_time: str | None = None
    ip_address: str | None = None
    url: str | None = None
    money: str | None = None
    credit_card: str | None = None
    crypto: str | None = None
    iban_code: str | None = None
    us_bank_number: str | None = None
    nif: str | None = None
    fin_nric: str | None = None
    au_abn: str | None = None
    au_acn: str | None = None
    au_tfn: str | None = None
    medical_license: str | None = None
    uk_nhs: str | None = None
    au_medicare: str | None = None
    us_drivers_license: str | None = None
    us_itin: str | None = None
    us_passport: str | None = None
    us_ssn: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> PIIEntity:
        if not data:
            return cls()
        return cls(**data)


@dataclass
class PromptInjection:
    disabled: bool | None = None
    action: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> PromptInjection:
        if not data:
            return cls()
        return cls(**data)


@dataclass
class SecretsDetection:
    disabled: bool | None = None
    slack_token: str | None = None
    ssh_dsa_private_key: str | None = None
    ssh_ec_private_key: str | None = None
    pgp_private_key_block: str | None = None
    amazon_aws_access_key_id: str | None = None
    amazon_aws_secret_access_key: str | None = None
    amazon_mws_auth_token: str | None = None
    facebook_access_token: str | None = None
    github_access_token: str | None = None
    jwt_token: str | None = None
    google_api_key: str | None = None
    google_cloud_platform_api_key: str | None = None
    google_drive_api_key: str | None = None
    google_cloud_platform_service_account: str | None = None
    google_gmail_api_key: str | None = None
    youtube_api_key: str | None = None
    mailchimp_api_key: str | None = None
    mailgun_api_key: str | None = None
    basic_auth: str | None = None
    picatic_api_key: str | None = None
    slack_webhook: str | None = None
    stripe_api_key: str | None = None
    stripe_restricted_api_key: str | None = None
    square_access_token: str | None = None
    square_oauth_secret: str | None = None
    twilio_api_key: str | None = None
    pangea_token: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> SecretsDetection:
        if not data:
            return cls()
        return cls(**data)


@dataclass
class Topic:
    disabled: bool | None = None
    action: str | None = None
    threshold: float | None = None
    topics: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> Topic:
        if not data:
            return cls()
        return cls(**data)
