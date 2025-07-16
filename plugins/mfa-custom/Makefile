PLUGIN_NAME= mfa
PLUGIN_VERSION= 1.0
PLUGIN_COMMENT= Custom Multi-Factor Authentication Plugin for OPNsense
PLUGIN_MAINTAINER= pierpaolo.casati@student.supsi.ch
PLUGIN_TIER= 3
PLUGIN_WWW= https://git.consoli.ch/students/20250400_lavsem/moretto/
PLUGIN_DIR= service

USES= python:3.11
USE_PYTHON= distutils

RUN_DEPENDS= ${PYTHON_PKGNAMEPREFIX}pyotp>=2.6.0:security/py-pyotp

.include "../../Mk/plugins.mk"