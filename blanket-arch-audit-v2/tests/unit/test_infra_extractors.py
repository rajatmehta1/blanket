"""Tests for infrastructure extractors (Docker, K8s, CI/CD, Terraform)."""
from __future__ import annotations

import pytest

from blanketaudit.ingestion.extractors.docker_extractor import DockerExtractor
from blanketaudit.ingestion.extractors.k8s_extractor import K8sExtractor
from blanketaudit.ingestion.extractors.cicd_extractor import CICDExtractor
from blanketaudit.ingestion.extractors.terraform_extractor import TerraformExtractor

# ══════════════════════════════════════════════════════════════
# Docker extractor tests
# ══════════════════════════════════════════════════════════════

SAMPLE_DOCKERFILE = """\
FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV APP_PORT=8080
EXPOSE 8080
EXPOSE 443
USER appuser
HEALTHCHECK --interval=30s CMD curl -f http://localhost:8080/health || exit 1
CMD ["uvicorn", "main:app"]
"""

DOCKERFILE_ROOT_USER = """\
FROM ubuntu:22.04
RUN apt-get update
USER root
EXPOSE 80
CMD ["nginx"]
"""

DOCKERFILE_LINE_CONTINUATION = """\
FROM alpine:3.18
RUN apk add --no-cache \\
    curl \\
    bash \\
    python3
EXPOSE 8080
"""

DOCKERFILE_NO_USER = """\
FROM node:20
RUN npm install
CMD ["node", "index.js"]
"""


class TestDockerExtractor:
    def setup_method(self):
        self.extractor = DockerExtractor()

    def test_extracts_base_image(self):
        result = self.extractor.extract("Dockerfile", SAMPLE_DOCKERFILE)
        assert result.base_image == "python:3.11-slim"

    def test_extracts_base_image_strips_as_alias(self):
        result = self.extractor.extract("Dockerfile", SAMPLE_DOCKERFILE)
        # "AS builder" should not appear in base_image
        assert "AS" not in result.base_image
        assert "builder" not in result.base_image

    def test_extracts_exposed_ports(self):
        result = self.extractor.extract("Dockerfile", SAMPLE_DOCKERFILE)
        assert sorted(result.exposed_ports) == [443, 8080]

    def test_detects_non_root_user(self):
        result = self.extractor.extract("Dockerfile", SAMPLE_DOCKERFILE)
        assert result.runs_as_root is False
        assert result.user == "appuser"

    def test_detects_root_user(self):
        result = self.extractor.extract("Dockerfile", DOCKERFILE_ROOT_USER)
        assert result.runs_as_root is True
        assert result.user == "root"

    def test_default_runs_as_root_when_no_user(self):
        result = self.extractor.extract("Dockerfile", DOCKERFILE_NO_USER)
        assert result.runs_as_root is True
        assert result.user == ""

    def test_detects_healthcheck(self):
        result = self.extractor.extract("Dockerfile", SAMPLE_DOCKERFILE)
        assert result.has_healthcheck is True

    def test_no_healthcheck(self):
        result = self.extractor.extract("Dockerfile", DOCKERFILE_ROOT_USER)
        assert result.has_healthcheck is False

    def test_env_vars_extracted(self):
        result = self.extractor.extract("Dockerfile", SAMPLE_DOCKERFILE)
        assert "APP_PORT" in result.env_vars

    def test_directive_count(self):
        result = self.extractor.extract("Dockerfile", SAMPLE_DOCKERFILE)
        # FROM, WORKDIR, COPY, RUN, COPY, ENV, EXPOSE, EXPOSE, USER, HEALTHCHECK, CMD = 11
        assert len(result.directives) == 11

    def test_line_continuation(self):
        result = self.extractor.extract("Dockerfile", DOCKERFILE_LINE_CONTINUATION)
        # The RUN with continuations should be collapsed into a single directive
        run_directives = [d for d in result.directives if d.instruction == "RUN"]
        assert len(run_directives) == 1
        assert "curl" in run_directives[0].value
        assert "bash" in run_directives[0].value

    def test_empty_dockerfile(self):
        result = self.extractor.extract("Dockerfile", "")
        assert result.base_image == ""
        assert result.directives == []
        assert result.exposed_ports == []

    def test_comment_lines_ignored(self):
        content = "# This is a comment\nFROM alpine:3.18\n# Another comment\n"
        result = self.extractor.extract("Dockerfile", content)
        assert len(result.directives) == 1
        assert result.base_image == "alpine:3.18"

    def test_file_path_preserved(self):
        result = self.extractor.extract("docker/Dockerfile.prod", SAMPLE_DOCKERFILE)
        assert result.file_path == "docker/Dockerfile.prod"
        assert all(d.file_path == "docker/Dockerfile.prod" for d in result.directives)


# ══════════════════════════════════════════════════════════════
# K8s extractor tests
# ══════════════════════════════════════════════════════════════

SAMPLE_K8S_DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
  namespace: production
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: api
          image: myapp:v1.2.3
          ports:
            - containerPort: 8080
          resources:
            limits:
              memory: "512Mi"
              cpu: "500m"
          securityContext:
            runAsNonRoot: true
            readOnlyRootFilesystem: true
"""

SAMPLE_K8S_PRIVILEGED = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: debug-pod
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: debug
          image: ubuntu:latest
          securityContext:
            privileged: true
            runAsUser: 0
"""

SAMPLE_K8S_SERVICE = """\
apiVersion: v1
kind: Service
metadata:
  name: api-lb
spec:
  type: LoadBalancer
  ports:
    - port: 80
    - port: 443
"""

SAMPLE_K8S_MULTI_DOC = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: web
          image: nginx:1.25
---
apiVersion: v1
kind: Service
metadata:
  name: web-svc
spec:
  type: ClusterIP
  ports:
    - port: 80
"""


class TestK8sExtractor:
    def setup_method(self):
        self.extractor = K8sExtractor()

    def test_deployment_basic(self):
        result = self.extractor.extract("deploy.yaml", SAMPLE_K8S_DEPLOYMENT)
        assert len(result.resources) == 1
        res = result.resources[0]
        assert res.kind == "Deployment"
        assert res.name == "api-server"
        assert res.namespace == "production"
        assert res.replicas == 3
        assert res.image == "myapp:v1.2.3"
        assert 8080 in res.ports
        assert res.resource_limits is True

    def test_deployment_security_context(self):
        result = self.extractor.extract("deploy.yaml", SAMPLE_K8S_DEPLOYMENT)
        res = result.resources[0]
        assert res.read_only_root is True
        # runAsNonRoot: true does NOT set runs_as_root (only runAsUser: 0 does)
        assert res.runs_as_root is False

    def test_privileged_container(self):
        result = self.extractor.extract("debug.yaml", SAMPLE_K8S_PRIVILEGED)
        res = result.resources[0]
        assert res.privileged is True
        assert res.runs_as_root is True
        assert res.host_network is True

    def test_service_extraction(self):
        result = self.extractor.extract("svc.yaml", SAMPLE_K8S_SERVICE)
        assert len(result.resources) == 1
        res = result.resources[0]
        assert res.kind == "Service"
        assert res.service_type == "LoadBalancer"
        assert sorted(res.ports) == [80, 443]

    def test_multi_document_yaml(self):
        result = self.extractor.extract("all.yaml", SAMPLE_K8S_MULTI_DOC)
        assert len(result.resources) == 2
        kinds = {r.kind for r in result.resources}
        assert kinds == {"Deployment", "Service"}

    def test_invalid_yaml(self):
        result = self.extractor.extract("bad.yaml", "{{{{not valid yaml: [")
        assert result.resources == []

    def test_non_k8s_yaml(self):
        result = self.extractor.extract("config.yaml", "database:\n  host: localhost\n  port: 5432\n")
        assert result.resources == []

    def test_default_namespace(self):
        result = self.extractor.extract("debug.yaml", SAMPLE_K8S_PRIVILEGED)
        assert result.resources[0].namespace == "default"

    def test_file_path_preserved(self):
        result = self.extractor.extract("k8s/prod/deploy.yaml", SAMPLE_K8S_DEPLOYMENT)
        assert result.file_path == "k8s/prod/deploy.yaml"
        assert result.resources[0].file_path == "k8s/prod/deploy.yaml"

    def test_empty_content(self):
        result = self.extractor.extract("empty.yaml", "")
        assert result.resources == []


# ══════════════════════════════════════════════════════════════
# CI/CD extractor tests
# ══════════════════════════════════════════════════════════════

SAMPLE_GITHUB_ACTIONS = """\
name: CI
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: npm test
      - name: Security scan
        uses: returntocorp/semgrep-action@v1
        env:
          SEMGREP_TOKEN: ${{ secrets.SEMGREP_TOKEN }}
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh
        env:
          AWS_KEY: ${{ secrets.AWS_ACCESS_KEY }}
"""

SAMPLE_GITLAB_CI = """\
stages:
  - test
  - deploy

unit_test:
  stage: test
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - pytest

security_scan:
  stage: test
  script:
    - semgrep --config auto .
"""

SAMPLE_GITHUB_ACTIONS_NO_SECRETS = """\
name: Lint
on: push
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run lint
"""


class TestCICDExtractor:
    def setup_method(self):
        self.extractor = CICDExtractor()

    def test_github_actions_platform(self):
        result = self.extractor.extract(".github/workflows/ci.yml", SAMPLE_GITHUB_ACTIONS)
        assert result.platform == "github_actions"

    def test_github_actions_triggers(self):
        result = self.extractor.extract(".github/workflows/ci.yml", SAMPLE_GITHUB_ACTIONS)
        assert "push" in result.triggers
        assert "pull_request" in result.triggers

    def test_github_actions_jobs(self):
        result = self.extractor.extract(".github/workflows/ci.yml", SAMPLE_GITHUB_ACTIONS)
        assert sorted(result.jobs) == ["deploy", "test"]

    def test_github_actions_secrets(self):
        result = self.extractor.extract(".github/workflows/ci.yml", SAMPLE_GITHUB_ACTIONS)
        assert result.uses_secrets is True
        # Check that specific secret names are captured
        all_secrets = []
        for step in result.steps:
            all_secrets.extend(step.secrets_used)
        assert "SEMGREP_TOKEN" in all_secrets
        assert "AWS_ACCESS_KEY" in all_secrets

    def test_github_actions_no_secrets(self):
        result = self.extractor.extract(".github/workflows/lint.yml", SAMPLE_GITHUB_ACTIONS_NO_SECRETS)
        assert result.uses_secrets is False

    def test_github_actions_security_scan(self):
        result = self.extractor.extract(".github/workflows/ci.yml", SAMPLE_GITHUB_ACTIONS)
        assert result.has_security_scan is True

    def test_github_actions_no_security_scan(self):
        result = self.extractor.extract(".github/workflows/lint.yml", SAMPLE_GITHUB_ACTIONS_NO_SECRETS)
        assert result.has_security_scan is False

    def test_gitlab_ci_detection(self):
        result = self.extractor.extract(".gitlab-ci.yml", SAMPLE_GITLAB_CI)
        assert result.platform == "gitlab_ci"

    def test_gitlab_ci_jobs(self):
        result = self.extractor.extract(".gitlab-ci.yml", SAMPLE_GITLAB_CI)
        assert "unit_test" in result.jobs
        assert "security_scan" in result.jobs

    def test_gitlab_ci_security_scan(self):
        result = self.extractor.extract(".gitlab-ci.yml", SAMPLE_GITLAB_CI)
        assert result.has_security_scan is True

    def test_gitlab_ci_steps_extracted(self):
        result = self.extractor.extract(".gitlab-ci.yml", SAMPLE_GITLAB_CI)
        # Each script line becomes a step
        run_commands = [s.run for s in result.steps]
        assert "pytest" in run_commands
        assert "semgrep --config auto ." in run_commands

    def test_gitlab_ci_image_extracted(self):
        result = self.extractor.extract(".gitlab-ci.yml", SAMPLE_GITLAB_CI)
        image_steps = [s for s in result.steps if s.image]
        # unit_test has image: python:3.11
        assert any(s.image == "python:3.11" for s in image_steps)

    def test_empty_yaml(self):
        result = self.extractor.extract("ci.yml", "")
        assert result.platform == "unknown"
        assert result.jobs == []

    def test_invalid_yaml(self):
        result = self.extractor.extract("ci.yml", "{{{{not valid yaml")
        assert result.platform == "unknown"
        assert result.jobs == []

    def test_file_path_preserved(self):
        result = self.extractor.extract(".github/workflows/ci.yml", SAMPLE_GITHUB_ACTIONS)
        assert result.file_path == ".github/workflows/ci.yml"


# ══════════════════════════════════════════════════════════════
# Terraform extractor tests
# ══════════════════════════════════════════════════════════════

SAMPLE_TERRAFORM = """\
provider "aws" {
  region = "us-east-1"
}

variable "environment" {
  type = string
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"

  server_side_encryption = "AES256"

  logging {
    target_bucket = "my-log-bucket"
  }
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port = 80
    to_port = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
}

output "bucket_arn" {
  value = aws_s3_bucket.data.arn
}
"""

SAMPLE_TERRAFORM_NO_ENCRYPTION = """\
resource "aws_s3_bucket" "plain" {
  bucket = "plain-bucket"
}
"""

SAMPLE_TERRAFORM_MULTI_PROVIDER = """\
provider "aws" {
  region = "us-east-1"
}

provider "google" {
  project = "my-project"
}

resource "aws_instance" "web" {
  ami = "ami-12345"
}

resource "google_compute_instance" "vm" {
  name = "test-vm"
}
"""


class TestTerraformExtractor:
    def setup_method(self):
        self.extractor = TerraformExtractor()

    def test_extracts_resources(self):
        result = self.extractor.extract("main.tf", SAMPLE_TERRAFORM)
        assert len(result.resources) == 2
        types = {r.resource_type for r in result.resources}
        assert types == {"aws_s3_bucket", "aws_security_group"}

    def test_resource_names(self):
        result = self.extractor.extract("main.tf", SAMPLE_TERRAFORM)
        names = {r.name for r in result.resources}
        assert names == {"data", "web"}

    def test_provider_inferred(self):
        result = self.extractor.extract("main.tf", SAMPLE_TERRAFORM)
        for res in result.resources:
            assert res.provider == "aws"

    def test_encryption_detected(self):
        result = self.extractor.extract("main.tf", SAMPLE_TERRAFORM)
        s3 = next(r for r in result.resources if r.resource_type == "aws_s3_bucket")
        assert s3.encryption_enabled is True

    def test_logging_detected(self):
        result = self.extractor.extract("main.tf", SAMPLE_TERRAFORM)
        s3 = next(r for r in result.resources if r.resource_type == "aws_s3_bucket")
        assert s3.logging_enabled is True

    def test_no_encryption_is_none(self):
        result = self.extractor.extract("main.tf", SAMPLE_TERRAFORM_NO_ENCRYPTION)
        res = result.resources[0]
        assert res.encryption_enabled is None

    def test_variables_extracted(self):
        result = self.extractor.extract("main.tf", SAMPLE_TERRAFORM)
        assert "environment" in result.variables

    def test_outputs_extracted(self):
        result = self.extractor.extract("main.tf", SAMPLE_TERRAFORM)
        assert "bucket_arn" in result.outputs

    def test_providers_extracted(self):
        result = self.extractor.extract("main.tf", SAMPLE_TERRAFORM)
        assert "aws" in result.providers

    def test_multi_provider(self):
        result = self.extractor.extract("main.tf", SAMPLE_TERRAFORM_MULTI_PROVIDER)
        assert sorted(result.providers) == ["aws", "google"]
        assert len(result.resources) == 2
        providers = {r.provider for r in result.resources}
        assert providers == {"aws", "google"}

    def test_line_numbers(self):
        result = self.extractor.extract("main.tf", SAMPLE_TERRAFORM)
        for res in result.resources:
            assert res.line_number >= 1

    def test_empty_file(self):
        result = self.extractor.extract("empty.tf", "")
        assert result.resources == []
        assert result.variables == []
        assert result.outputs == []
        assert result.providers == []

    def test_file_path_preserved(self):
        result = self.extractor.extract("infra/main.tf", SAMPLE_TERRAFORM)
        assert result.file_path == "infra/main.tf"
        assert all(r.file_path == "infra/main.tf" for r in result.resources)

    def test_security_group_no_encryption_field(self):
        result = self.extractor.extract("main.tf", SAMPLE_TERRAFORM)
        sg = next(r for r in result.resources if r.resource_type == "aws_security_group")
        assert sg.encryption_enabled is None
