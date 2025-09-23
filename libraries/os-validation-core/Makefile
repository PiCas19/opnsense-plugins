PLUGIN_NAME=		validation-core
PLUGIN_VERSION=		1.0
PLUGIN_COMMENT=		OPNsense Validation Core Library - Shared validation framework
PLUGIN_MAINTAINER=	pierpaolo.casati@student.supsi.ch
PLUGIN_TIER=		1

.include "../../Mk/plugins.mk"

# Custom installation for shared library
post-install:
	@${ECHO_MSG} "Installing ValidationCore shared library..."
	@${MKDIR} -p ${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore
	@${MKDIR} -p ${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore/Utils
	@${MKDIR} -p ${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore/Validators
	
	# Copy ValidationCore files to system library directory
	@${CP} ${WRKSRC}/src/opnsense/mvc/app/library/OPNsense/ValidationCore/ValidationEngine.php \
		${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore/
	@${CP} ${WRKSRC}/src/opnsense/mvc/app/library/OPNsense/ValidationCore/Utils/*.php \
		${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore/Utils/
	@${CP} ${WRKSRC}/src/opnsense/mvc/app/library/OPNsense/ValidationCore/Validators/*.php \
		${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore/Validators/
	
	# Set proper permissions
	@${FIND} ${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore \
		-type f -name "*.php" -exec ${CHMOD} 644 {} \;
	@${FIND} ${STAGEDIR}${PREFIX}/opnsense/mvc/app/library/OPNsense/ValidationCore \
		-type d -exec ${CHMOD} 755 {} \;
	
	@${ECHO_MSG} "ValidationCore library installed successfully"

# Development helper
dev-install:
	@${ECHO_MSG} "Installing ValidationCore for development..."
	@${MKDIR} -p /usr/local/opnsense/mvc/app/library/OPNsense/ValidationCore
	@${CP} -r ${.CURDIR}/src/opnsense/mvc/app/library/OPNsense/ValidationCore/* \
		/usr/local/opnsense/mvc/app/library/OPNsense/ValidationCore/
	@${CHOWN} -R root:wheel /usr/local/opnsense/mvc/app/library/OPNsense/ValidationCore/
	@service configd restart
	@${ECHO_MSG} "Development installation complete"