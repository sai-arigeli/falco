set(CPACK_PACKAGE_NAME "${PACKAGE_NAME}")
set(CPACK_PACKAGE_VENDOR "Cloud Native Computing Foundation (CNCF) cncf.io.")
set(CPACK_PACKAGE_CONTACT "opensource@sysdig.com") # todo: change this once we've got @falco.org addresses
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Falco - Container Native Runtime Security")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/scripts/description.txt")
set(CPACK_PACKAGE_VERSION "${FALCO_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PROJECT_CONFIG_FILE "${PROJECT_SOURCE_DIR}/CMakeCPackOptions.cmake")
set(CPACK_STRIP_FILES "ON")
set(CPACK_PACKAGE_RELOCATABLE "OFF")

set(CPACK_GENERATOR DEB RPM TGZ)

set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://www.falco.org")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "dkms (>= 2.1.0.0)")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_BINARY_DIR}/scripts/debian/postinst;${CMAKE_BINARY_DIR}/scripts/debian/prerm;${PROJECT_SOURCE_DIR}/scripts/debian/postrm;${PROJECT_SOURCE_DIR}/cmake/cpack/debian/conffiles")

set(CPACK_RPM_PACKAGE_LICENSE "Apache v2.0")
set(CPACK_RPM_PACKAGE_URL "https://www.falco.org")
set(CPACK_RPM_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postuninstall")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /usr/src /usr/share/man /usr/share/man/man8 /etc /usr /usr/bin /usr/share /etc/rc.d /etc/rc.d/init.d)
set(CPACK_RPM_PACKAGE_RELOCATABLE "OFF")

if(CPACK_GENERATOR MATCHES "DEB")
	list(APPEND CPACK_INSTALL_COMMANDS "mkdir -p _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/etc/init.d/")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/debian/falco _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/etc/init.d")
endif()

if(CPACK_GENERATOR MATCHES "RPM")
	list(APPEND CPACK_INSTALL_COMMANDS "mkdir -p _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/etc/rc.d/init.d/")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/rpm/falco _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/etc/rc.d/init.d")
endif()

if(CPACK_GENERATOR MATCHES "TGZ")
	set(CPACK_SET_DESTDIR "ON")
	set(CPACK_STRIP_FILES "OFF")
endif()

include(CPack)