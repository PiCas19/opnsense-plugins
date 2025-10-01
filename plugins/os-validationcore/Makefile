PLUGIN_NAME= validationcore
PLUGIN_VERSION= 1.0
PLUGIN_COMMENT= Validation Core Library for OPNsense plugins
PLUGIN_MAINTAINER= pierpaolo.casati@student.supsi.ch
PLUGIN_TIER= 3
PLUGIN_WWW= https://git.consoli.ch/students/20250400_lavsem/moretto/

.include "../../Mk/plugins.mk"

do-install:
	${MKDIR} -p ${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore/Utils
	${MKDIR} -p ${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore/Validators
	(cd ${WRKSRC}/src/opnsense && ${COPYTREE_SHARE} . ${STAGEDIR}${PREFIX}/opnsense)