use anyhow::Result;
use windows::core::BSTR;
use windows::w;
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::System::Com::CoCreateInstance;
use windows::Win32::System::Com::CoInitializeEx;
use windows::Win32::System::Com::CoInitializeSecurity;
use windows::Win32::System::Com::CLSCTX_INPROC_SERVER;
use windows::Win32::System::Com::COINIT_MULTITHREADED;
use windows::Win32::System::Com::EOAC_NONE;
use windows::Win32::System::Com::RPC_C_AUTHN_LEVEL_DEFAULT;
use windows::Win32::System::Com::RPC_C_IMP_LEVEL_IMPERSONATE;
use windows::Win32::System::Ole::VarFormat;
use windows::Win32::System::Ole::VariantClear;
use windows::Win32::System::Ole::VARFORMAT_FIRST_DAY_SYSTEMDEFAULT;
use windows::Win32::System::Ole::VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT;
use windows::Win32::System::Wmi::IWbemLocator;
use windows::Win32::System::Wmi::IWbemServices;
use windows::Win32::System::Wmi::WbemLocator;
use windows::Win32::System::Wmi::WBEM_FLAG_FORWARD_ONLY;
use windows::Win32::System::Wmi::WBEM_FLAG_RETURN_IMMEDIATELY;

const VM_SETTINGS_QUERY: &str = "SELECT * FROM Msvm_VirtualSystemSettingData";
const VM_STATUS_QUERY: &str = "SELECT * FROM Msvm_ComputerSystem";

#[derive(Debug)]
#[allow(dead_code)]
struct HyperVVmSettings {
    virtual_system_identifier: String,
    configuration_data_root: String,
    configuration_file: String,
    firmware_file: String,
    firmware_parameters: String,
    guest_state_data_root: String,
    guest_state_file: String,
    guest_state_isolation_enabled: String,
    guest_state_isolation_type: String,
    is_saved: String,
    virtual_system_sub_type: String,
    secure_boot_enabled: String,
    turn_off_on_guest_restart: String,
}

#[derive(Debug)]
#[allow(dead_code)]
struct HyperVVmStatus {
    available_requested_states: String,
    caption: String,
    communication_status: String,
    creation_class_name: String,
    dedicated: String,
    description: String,
    detailed_status: String,
    element_name: String,
    enabled_default: String,
    enabled_state: String,
    enhanced_session_mode_state: String,
    failed_over_replication_type: String,
    health_state: String,
    hw_threads_per_core_realized: String,
    identifying_descriptions: String,
    install_date: String,
    instance_id: String,
    last_application_consistent_replication_time: String,
    last_replication_time: String,
    last_replication_type: String,
    last_successful_backup_time: String,
    name: String,
    name_format: String,
    number_of_numa_nodes: String,
    on_time_in_milliseconds: String,
    operating_status: String,
    operational_status: String,
    other_dedicated_descriptions: String,
    other_enabled_state: String,
    other_identifying_info: String,
    power_management_capabilities: String,
    primary_owner_contact: String,
    primary_owner_name: String,
    primary_status: String,
    process_id: String,
    replication_health: String,
    replication_mode: String,
    replication_state: String,
    requested_state: String,
    reset_capability: String,
    roles: String,
    status: String,
    status_descriptions: String,
    time_of_last_configuration_change: String,
    time_of_last_state_change: String,
    transitioning_to_state: String,
}

fn init_com() -> Result<()> {
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED)?;
        CoInitializeSecurity(
            PSECURITY_DESCRIPTOR::default(),
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )?;
    }

    Ok(())
}

fn connect_hyperv_wmi() -> Result<IWbemServices> {
    let server = unsafe {
        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
        locator.ConnectServer(
            &BSTR::from("root\\virtualization\\v2"),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        )?
    };

    Ok(server)
}

fn get_hyperv_vm_settings(server: &IWbemServices, vm_name: &str) -> Result<HyperVVmSettings> {
    unsafe {
        let query = format!("{VM_SETTINGS_QUERY} WHERE ElementName='{}'", vm_name);
        let query = server.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from(query),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )?;

        let mut row = [None; 1];
        let mut returned = 0;

        query.Next(-1, &mut row, &mut returned).ok()?;
        if let Some(row) = &row[0] {
            let mut virtual_system_identifier_var = Default::default();
            let mut configuration_data_root_var = Default::default();
            let mut configuration_file_var = Default::default();
            let mut firmware_file_var = Default::default();
            let mut firmware_parameters_var = Default::default();
            let mut guest_state_data_root_var = Default::default();
            let mut guest_state_file_var = Default::default();
            let mut guest_state_isolation_enabled_var = Default::default();
            let mut guest_state_isolation_type_var = Default::default();
            let mut is_saved_var = Default::default();
            let mut virtual_system_sub_type_var = Default::default();
            let mut secure_boot_enabled_var = Default::default();
            let mut turn_off_on_guest_restart_var = Default::default();

            row.Get(
                w!("VirtualSystemIdentifier"),
                0,
                &mut virtual_system_identifier_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            row.Get(
                w!("ConfigurationDataRoot"),
                0,
                &mut configuration_data_root_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            row.Get(
                w!("ConfigurationFile"),
                0,
                &mut configuration_file_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            row.Get(
                w!("FirmwareFile"),
                0,
                &mut firmware_file_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            row.Get(
                w!("FirmwareParameters"),
                0,
                &mut firmware_parameters_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            row.Get(
                w!("GuestStateDataRoot"),
                0,
                &mut guest_state_data_root_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            row.Get(
                w!("GuestStateFile"),
                0,
                &mut guest_state_file_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            row.Get(
                w!("GuestStateIsolationEnabled"),
                0,
                &mut guest_state_isolation_enabled_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            row.Get(
                w!("GuestStateIsolationType"),
                0,
                &mut guest_state_isolation_type_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            row.Get(
                w!("IsSaved"),
                0,
                &mut is_saved_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            row.Get(
                w!("VirtualSystemSubType"),
                0,
                &mut virtual_system_sub_type_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            row.Get(
                w!("SecureBootEnabled"),
                0,
                &mut secure_boot_enabled_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            row.Get(
                w!("TurnOffOnGuestRestart"),
                0,
                &mut turn_off_on_guest_restart_var,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;

            let virtual_system_identifier = VarFormat(
                &virtual_system_identifier_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;
            let configuration_data_root = VarFormat(
                &configuration_data_root_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;
            let configuration_file = VarFormat(
                &configuration_file_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;
            let firmware_file = VarFormat(
                &firmware_file_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;
            let firmware_parameters = VarFormat(
                &firmware_parameters_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;
            let guest_state_data_root = VarFormat(
                &guest_state_data_root_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;
            let guest_state_file = VarFormat(
                &guest_state_file_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;
            let guest_state_isolation_enabled = VarFormat(
                &guest_state_isolation_enabled_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;
            let guest_state_isolation_type = VarFormat(
                &guest_state_isolation_type_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;
            let is_saved = VarFormat(
                &is_saved_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;
            let virtual_system_sub_type = VarFormat(
                &virtual_system_sub_type_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;
            let secure_boot_enabled = VarFormat(
                &secure_boot_enabled_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;
            let turn_off_on_guest_restart = VarFormat(
                &turn_off_on_guest_restart_var,
                None,
                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                0,
            )?;

            VariantClear(&mut virtual_system_identifier_var)?;
            VariantClear(&mut configuration_data_root_var)?;
            VariantClear(&mut configuration_file_var)?;
            VariantClear(&mut firmware_file_var)?;
            VariantClear(&mut firmware_parameters_var)?;
            VariantClear(&mut guest_state_data_root_var)?;
            VariantClear(&mut guest_state_file_var)?;
            VariantClear(&mut guest_state_isolation_enabled_var)?;
            VariantClear(&mut guest_state_isolation_type_var)?;
            VariantClear(&mut is_saved_var)?;
            VariantClear(&mut virtual_system_sub_type_var)?;
            VariantClear(&mut secure_boot_enabled_var)?;
            VariantClear(&mut turn_off_on_guest_restart_var)?;

            let virtual_system_identifier =
                String::from_utf16(virtual_system_identifier.as_wide())?;
            let configuration_data_root = String::from_utf16(configuration_data_root.as_wide())?;
            let configuration_file = String::from_utf16(configuration_file.as_wide())?;
            let firmware_file = String::from_utf16(firmware_file.as_wide())?;
            let firmware_parameters = String::from_utf16(firmware_parameters.as_wide())?;
            let guest_state_data_root = String::from_utf16(guest_state_data_root.as_wide())?;
            let guest_state_file = String::from_utf16(guest_state_file.as_wide())?;
            let guest_state_isolation_enabled =
                String::from_utf16(guest_state_isolation_enabled.as_wide())?;
            let guest_state_isolation_type =
                String::from_utf16(guest_state_isolation_type.as_wide())?;
            let is_saved = String::from_utf16(is_saved.as_wide())?;
            let virtual_system_sub_type = String::from_utf16(virtual_system_sub_type.as_wide())?;
            let secure_boot_enabled = String::from_utf16(secure_boot_enabled.as_wide())?;
            let turn_off_on_guest_restart =
                String::from_utf16(turn_off_on_guest_restart.as_wide())?;

            Ok(HyperVVmSettings {
                virtual_system_identifier,
                configuration_data_root,
                configuration_file,
                firmware_file,
                firmware_parameters,
                guest_state_data_root,
                guest_state_file,
                guest_state_isolation_enabled,
                guest_state_isolation_type,
                is_saved,
                virtual_system_sub_type,
                secure_boot_enabled,
                turn_off_on_guest_restart,
            })
        } else {
            anyhow::bail!("Not found")
        }
    }
}

/*
fn get_hyperv_vm_status() -> Result<HyperVVmStatus> {
    // AvailableRequestedStates
    // Caption
    // CommunicationStatus
    // CreationClassName
    // Dedicated
    // Description
    // DetailedStatus
    // ElementName
    // EnabledDefault
    // EnabledState
    // EnhancedSessionModeState
    // FailedOverReplicationType
    // HealthState
    // HwThreadsPerCoreRealized
    // IdentifyingDescriptions
    // InstallDate
    // InstanceID
    // LastApplicationConsistentReplicationTime
    // LastReplicationTime
    // LastReplicationType
    // LastSuccessfulBackupTime
    // Name
    // NameFormat
    // NumberOfNumaNodes
    // OnTimeInMilliseconds
    // OperatingStatus
    // OperationalStatus
    // OtherDedicatedDescriptions
    // OtherEnabledState
    // OtherIdentifyingInfo
    // PowerManagementCapabilities
    // PrimaryOwnerContact
    // PrimaryOwnerName
    // PrimaryStatus
    // ProcessID
    // ReplicationHealth
    // ReplicationMode
    // ReplicationState
    // RequestedState
    // ResetCapability
    // Roles
    // Status
    // StatusDescriptions
    // TimeOfLastConfigurationChange
    // TimeOfLastStateChange
    // TransitioningToState
}
*/

fn main() -> Result<()> {
    init_com()?;

    let server = connect_hyperv_wmi()?;
    let settings = get_hyperv_vm_settings(&server, "alpine")?;

    println!("{settings:#?}");

    Ok(())
}
