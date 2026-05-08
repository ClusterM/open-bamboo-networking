# Maps OBN_CLIENT_TYPE to client-specific install settings.
#
# The plugin's source code does not change between clients — they all load
# the same C ABI from the same .so. What differs is the slicer's plugin-
# loader convention, the OTA manifest scheme, and the conf file we patch
# at install time:
#
#   bambu_studio
#     - dlopens "<data_dir>/plugins/libbambu_networking.so" by fixed name
#     - reads the cached version from
#       <data_dir>/ota/plugins/network_plugins.json before deciding
#       whether to redownload from the cloud
#     - first-time install needs "installed_networking" / "update_network_plugin"
#       toggled in BambuStudio.conf
#
#   orca_slicer
#     - dlopens "<data_dir>/plugins/libbambu_networking_<network_plugin_version>.so"
#       — the version is part of the file name, so we ship a renamed copy
#     - does NOT read network_plugins.json on startup; that file is only
#       a transient artefact dropped by an OTA update flow and deleted
#       afterwards (see PresetUpdater.cpp). Skip it entirely on install.
#     - first-time install needs installed_networking=true,
#       network_plugin_version=<OBN_VERSION>, network_plugin_remind_later
#       set, and our version stripped from network_plugin_skipped_versions
#       in OrcaSlicer.conf
#
# obn_resolve_client(type) sets the following variables in the caller's
# scope (PARENT_SCOPE):
#
#   OBN_CLIENT_PLUGIN_NAME
#       Base name of the libbambu_networking shared object on disk
#       (without "lib" prefix or ".so" suffix). Studio: "bambu_networking";
#       Orca: "bambu_networking_<OBN_VERSION>".
#
#   OBN_CLIENT_INSTALL_OTA
#       TRUE if network_plugins.json should be installed at all.
#       Only Studio uses it as a persistent manifest; Orca does not.
#
#   OBN_CLIENT_OTA_SUBPATH
#       Relative install dir for network_plugins.json when OBN_CLIENT_INSTALL_OTA
#       is TRUE. Studio expects "ota/plugins". Empty otherwise.
#
#   OBN_CLIENT_CONF_PATCH_SCRIPT
#       Absolute path to the .cmake.in template used by install(SCRIPT) to
#       patch the slicer's conf file. configure_file() expands @VAR@
#       references against the current CMake variables.
#
#   OBN_CLIENT_CONF_NAME
#       File name of the slicer's conf file ("BambuStudio.conf" or
#       "OrcaSlicer.conf"). Used by the patch script template and by the
#       "expected install prefix" gate.
#
#   OBN_CLIENT_DEFAULT_PREFIX
#       Recommended default install prefix (Linux only). Native config
#       dir is preferred; the Flatpak config dir
#       (~/.var/app/<app-id>/config/<dir>) is used only when the native
#       one is missing AND the Flatpak one exists. Empty on non-Linux
#       or when $HOME is unset.
#
#   OBN_CLIENT_EXPECTED_PREFIXES
#       Semicolon-separated list of install-time prefixes where the
#       conf-patch script is allowed to run. Contains both the native
#       and the Flatpak path for the selected client so a user who
#       passed --prefix= to either still gets the patch.

function(obn_resolve_client client_type)
    if(NOT client_type STREQUAL "bambu_studio" AND
       NOT client_type STREQUAL "orca_slicer")
        message(FATAL_ERROR
            "obn_resolve_client: unknown client_type '${client_type}'. "
            "Must be 'bambu_studio' or 'orca_slicer'.")
    endif()

    set(_module_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}")

    if(DEFINED ENV{HOME} AND NOT "$ENV{HOME}" STREQUAL "")
        set(_home "$ENV{HOME}")
    else()
        set(_home "")
    endif()

    if(client_type STREQUAL "bambu_studio")
        set(OBN_CLIENT_PLUGIN_NAME       "bambu_networking"                          PARENT_SCOPE)
        set(OBN_CLIENT_INSTALL_OTA       TRUE                                         PARENT_SCOPE)
        set(OBN_CLIENT_OTA_SUBPATH       "ota/plugins"                                PARENT_SCOPE)
        set(OBN_CLIENT_CONF_PATCH_SCRIPT "${_module_dir}/patch_bambustudio_conf.cmake.in" PARENT_SCOPE)
        set(OBN_CLIENT_CONF_NAME         "BambuStudio.conf"                           PARENT_SCOPE)
        set(_client_native  "${_home}/.config/BambuStudio")
        set(_client_flatpak "${_home}/.var/app/com.bambulab.BambuStudio/config/BambuStudio")
    else() # orca_slicer
        if(NOT DEFINED OBN_VERSION OR OBN_VERSION STREQUAL "")
            message(FATAL_ERROR
                "obn_resolve_client(orca_slicer): OBN_VERSION must be set "
                "before calling obn_resolve_client (it is part of the .so file name).")
        endif()
        set(OBN_CLIENT_PLUGIN_NAME       "bambu_networking_${OBN_VERSION}"            PARENT_SCOPE)
        set(OBN_CLIENT_INSTALL_OTA       FALSE                                        PARENT_SCOPE)
        set(OBN_CLIENT_OTA_SUBPATH       ""                                           PARENT_SCOPE)
        set(OBN_CLIENT_CONF_PATCH_SCRIPT "${_module_dir}/patch_orcaslicer_conf.cmake.in" PARENT_SCOPE)
        set(OBN_CLIENT_CONF_NAME         "OrcaSlicer.conf"                            PARENT_SCOPE)
        set(_client_native  "${_home}/.config/OrcaSlicer")
        set(_client_flatpak "${_home}/.var/app/com.orcaslicer.OrcaSlicer/config/OrcaSlicer")
    endif()

    # Native preferred; Flatpak only as a fallback when native is missing.
    # Mirrors the priority in ./configure. Same shape for both clients.
    if(UNIX AND NOT APPLE AND NOT _home STREQUAL "")
        if(IS_DIRECTORY "${_client_native}")
            set(OBN_CLIENT_DEFAULT_PREFIX "${_client_native}"  PARENT_SCOPE)
        elseif(IS_DIRECTORY "${_client_flatpak}")
            set(OBN_CLIENT_DEFAULT_PREFIX "${_client_flatpak}" PARENT_SCOPE)
        else()
            set(OBN_CLIENT_DEFAULT_PREFIX "${_client_native}"  PARENT_SCOPE)
        endif()
        set(OBN_CLIENT_EXPECTED_PREFIXES "${_client_native};${_client_flatpak}" PARENT_SCOPE)
    else()
        set(OBN_CLIENT_DEFAULT_PREFIX     ""  PARENT_SCOPE)
        set(OBN_CLIENT_EXPECTED_PREFIXES  ""  PARENT_SCOPE)
    endif()
endfunction()
