# libraries/os-validation-core/Makefile

PLUGIN_NAME=		os-validation-core
PLUGIN_VERSION=		1.0
PLUGIN_COMMENT=		OPNsense Validation Core Library
PLUGIN_DEPENDS=		
PLUGIN_MAINTAINER=	Pierpaolo Casati

# This is a library package, not a plugin
PLUGIN_NOPREFIX=	yes

.include "../../Mk/libraries.mk"

# Custom installation for validation core library
post-install:
	# Create library directory structure
	@${MKDIR} -p ${STAGEDIR}/usr/local/opnsense/mvc/app/library/OPNsense/ValidationCore
	@${MKDIR} -p ${STAGEDIR}/usr/local/opnsense/mvc/app/library/OPNsense/ValidationCore/Validators
	@${MKDIR} -p ${STAGEDIR}/usr/local/opnsense/mvc/app/library/OPNsense/ValidationCore/Utils
	
	# Copy validation core library files
	@${CP} -r ${WRKSRC}/src/opnsense/mvc/app/library/OPNsense/ValidationCore/* \
		${STAGEDIR}/usr/local/opnsense/mvc/app/library/OPNsense/ValidationCore/
	
	# Set proper permissions for all PHP files
	@${FIND} ${STAGEDIR}/usr/local/opnsense/mvc/app/library/OPNsense/ValidationCore \
		-type f -name "*.php" -exec ${CHMOD} 644 {} \;

# Development install target
dev-install:
	scp -r src/opnsense/mvc/app/library/OPNsense/ValidationCore/* \
		root@opnsense-dev:/usr/local/opnsense/mvc/app/library/OPNsense/ValidationCore/