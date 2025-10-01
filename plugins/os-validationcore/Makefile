PLUGIN_NAME=        validationcore
PLUGIN_VERSION=     1.0
PLUGIN_COMMENT=     Validation Core Library for OPNsense plugins
PLUGIN_MAINTAINER=  pierpaolo.casati@student.supsi.ch
PLUGIN_TIER=        3
PLUGIN_WWW=         https://git.consoli.ch/students/20250400_lavsem/moretto/

.include "../../Mk/plugins.mk"

do-install:
	@echo "=== DEBUG INFO ==="
	@echo "WRKSRC: ${WRKSRC}"
	@echo "PREFIX: ${PREFIX}"
	@echo "STAGEDIR: ${STAGEDIR}"
	@ls -la ${WRKSRC}/ || true
	@ls -la ${WRKSRC}/src/ || true
	@ls -la ${WRKSRC}/src/mvc/app/library/OPNsense/ || true
	@echo "=================="
	${MKDIR} -p ${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore/Utils
	${MKDIR} -p ${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore/Validators
	${CP} -R ${WRKSRC}/src/mvc/app/library/OPNsense/ValidationCore/* \
		${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore/
	@echo "=== Files copied ==="
	@ls -la ${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ || true