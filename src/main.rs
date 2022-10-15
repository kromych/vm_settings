use anyhow::Result;
use windows::core::BSTR;
use windows::core::PCWSTR;
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::System::Com::CoCreateInstance;
use windows::Win32::System::Com::CoInitializeEx;
use windows::Win32::System::Com::CoInitializeSecurity;
use windows::Win32::System::Com::CLSCTX_INPROC_SERVER;
use windows::Win32::System::Com::COINIT_MULTITHREADED;
use windows::Win32::System::Com::EOAC_NONE;
use windows::Win32::System::Com::RPC_C_AUTHN_LEVEL_DEFAULT;
use windows::Win32::System::Com::RPC_C_IMP_LEVEL_IMPERSONATE;
use windows::Win32::System::Com::VARIANT;
use windows::Win32::System::Ole::VarFormat;
use windows::Win32::System::Ole::VariantClear;
use windows::Win32::System::Ole::VARFORMAT_FIRST_DAY_SYSTEMDEFAULT;
use windows::Win32::System::Ole::VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT;
use windows::Win32::System::Wmi::IWbemClassObject;
use windows::Win32::System::Wmi::IWbemLocator;
use windows::Win32::System::Wmi::IWbemServices;
use windows::Win32::System::Wmi::WbemLocator;
use windows::Win32::System::Wmi::WBEM_FLAG_FORWARD_ONLY;
use windows::Win32::System::Wmi::WBEM_FLAG_RETURN_IMMEDIATELY;

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

fn get_row_item(o: &IWbemClassObject, name: &str) -> Result<String> {
    let mut value: VARIANT = Default::default();
    let wide_name = name.encode_utf16().collect::<Vec<_>>().as_ptr();
    unsafe {
        o.Get(
            PCWSTR(wide_name),
            0,
            &mut value,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )?;

        let bstr = VarFormat(
            &value,
            None,
            VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
            VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
            0,
        )?;

        VariantClear(&mut value)?;
        Ok(String::from_utf16(bstr.as_wide())?)
    }
}

trait WmiRowConstructable<T> {
    fn from_row(row: &IWbemClassObject) -> Result<T>;
    fn query_one(key: &str) -> String;
}

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

impl WmiRowConstructable<HyperVVmSettings> for HyperVVmSettings {
    fn from_row(row: &IWbemClassObject) -> Result<HyperVVmSettings> {
        Ok(HyperVVmSettings {
            virtual_system_identifier: get_row_item(row, "VirtualSystemIdentifier")
                .unwrap_or_default(),
            configuration_data_root: get_row_item(row, "ConfigurationDataRoot").unwrap_or_default(),
            configuration_file: get_row_item(row, "ConfigurationFile").unwrap_or_default(),
            firmware_file: get_row_item(row, "FirmwareFile").unwrap_or_default(),
            firmware_parameters: get_row_item(row, "FirmwareParameters").unwrap_or_default(),
            guest_state_data_root: get_row_item(row, "GuestStateDataRoot").unwrap_or_default(),
            guest_state_file: get_row_item(row, "GuestStateFile").unwrap_or_default(),
            guest_state_isolation_enabled: get_row_item(row, "GuestStateIsolationEnabled")
                .unwrap_or_default(),
            guest_state_isolation_type: get_row_item(row, "GuestStateIsolationType")
                .unwrap_or_default(),
            is_saved: get_row_item(row, "IsSaved").unwrap_or_default(),
            virtual_system_sub_type: get_row_item(row, "VirtualSystemSubType").unwrap_or_default(),
            secure_boot_enabled: get_row_item(row, "SecureBootEnabled").unwrap_or_default(),
            turn_off_on_guest_restart: get_row_item(row, "TurnOffOnGuestRestart")
                .unwrap_or_default(),
        })
    }

    fn query_one(key: &str) -> String {
        format!("SELECT * FROM Msvm_VirtualSystemSettingData WHERE ElementName='{key}'")
    }
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

impl WmiRowConstructable<HyperVVmStatus> for HyperVVmStatus {
    fn from_row(row: &IWbemClassObject) -> Result<HyperVVmStatus> {
        Ok(HyperVVmStatus {
            available_requested_states: get_row_item(row, "AvailableRequestedStates")
                .unwrap_or_default(),
            caption: get_row_item(row, "Caption").unwrap_or_default(),
            communication_status: get_row_item(row, "CommunicationStatus").unwrap_or_default(),
            creation_class_name: get_row_item(row, "CreationClassName").unwrap_or_default(),
            dedicated: get_row_item(row, "Dedicated").unwrap_or_default(),
            description: get_row_item(row, "Description").unwrap_or_default(),
            detailed_status: get_row_item(row, "DetailedStatus").unwrap_or_default(),
            element_name: get_row_item(row, "ElementName").unwrap_or_default(),
            enabled_default: get_row_item(row, "EnabledDefault").unwrap_or_default(),
            enabled_state: get_row_item(row, "EnabledState").unwrap_or_default(),
            enhanced_session_mode_state: get_row_item(row, "EnhancedSessionModeState")
                .unwrap_or_default(),
            failed_over_replication_type: get_row_item(row, "FailedOverReplicationType")
                .unwrap_or_default(),
            health_state: get_row_item(row, "HealthState").unwrap_or_default(),
            hw_threads_per_core_realized: get_row_item(row, "HwThreadsPerCoreRealized")
                .unwrap_or_default(),
            identifying_descriptions: get_row_item(row, "IdentifyingDescriptions")
                .unwrap_or_default(),
            install_date: get_row_item(row, "InstallDate").unwrap_or_default(),
            instance_id: get_row_item(row, "InstanceID").unwrap_or_default(),
            last_application_consistent_replication_time: get_row_item(
                row,
                "LastApplicationConsistentReplicationTime",
            )
            .unwrap_or_default(),
            last_replication_time: get_row_item(row, "LastReplicationTime").unwrap_or_default(),
            last_replication_type: get_row_item(row, "LastReplicationType").unwrap_or_default(),
            last_successful_backup_time: get_row_item(row, "LastSuccessfulBackupTime")
                .unwrap_or_default(),
            name: get_row_item(row, "Name").unwrap_or_default(),
            name_format: get_row_item(row, "NameFormat").unwrap_or_default(),
            number_of_numa_nodes: get_row_item(row, "NumberOfNumaNodes").unwrap_or_default(),
            on_time_in_milliseconds: get_row_item(row, "OnTimeInMilliseconds").unwrap_or_default(),
            operating_status: get_row_item(row, "OperatingStatus").unwrap_or_default(),
            operational_status: get_row_item(row, "OperationalStatus").unwrap_or_default(),
            other_dedicated_descriptions: get_row_item(row, "OtherDedicatedDescriptions")
                .unwrap_or_default(),
            other_enabled_state: get_row_item(row, "OtherEnabledState").unwrap_or_default(),
            other_identifying_info: get_row_item(row, "OtherIdentifyingInfo").unwrap_or_default(),
            power_management_capabilities: get_row_item(row, "PowerManagementCapabilities")
                .unwrap_or_default(),
            primary_owner_contact: get_row_item(row, "PrimaryOwnerContact").unwrap_or_default(),
            primary_owner_name: get_row_item(row, "PrimaryOwnerName").unwrap_or_default(),
            primary_status: get_row_item(row, "PrimaryStatus").unwrap_or_default(),
            process_id: get_row_item(row, "ProcessID").unwrap_or_default(),
            replication_health: get_row_item(row, "ReplicationHealth").unwrap_or_default(),
            replication_mode: get_row_item(row, "ReplicationMode").unwrap_or_default(),
            replication_state: get_row_item(row, "ReplicationState").unwrap_or_default(),
            requested_state: get_row_item(row, "RequestedState").unwrap_or_default(),
            reset_capability: get_row_item(row, "ResetCapability").unwrap_or_default(),
            roles: get_row_item(row, "Roles").unwrap_or_default(),
            status: get_row_item(row, "Status").unwrap_or_default(),
            status_descriptions: get_row_item(row, "StatusDescriptions").unwrap_or_default(),
            time_of_last_configuration_change: get_row_item(row, "TimeOfLastConfigurationChange")
                .unwrap_or_default(),
            time_of_last_state_change: get_row_item(row, "TimeOfLastStateChange")
                .unwrap_or_default(),
            transitioning_to_state: get_row_item(row, "TransitioningToState").unwrap_or_default(),
        })
    }

    fn query_one(key: &str) -> String {
        format!("SELECT * FROM Msvm_ComputerSystem WHERE ElementName='{key}'")
    }
}

fn query_one<T>(server: &IWbemServices, vm_name: &str) -> Result<T>
where
    T: WmiRowConstructable<T>,
{
    unsafe {
        let query = T::query_one(vm_name);
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
            Ok(T::from_row(row)?)
        } else {
            anyhow::bail!("Not found")
        }
    }
}

fn main() -> Result<()> {
    init_com()?;

    let server = connect_hyperv_wmi()?;
    let status = query_one::<HyperVVmStatus>(&server, "alpine")?;
    println!("{status:#?}");

    let settings = query_one::<HyperVVmSettings>(&server, "alpine")?;
    println!("{settings:#?}");

    Ok(())
}
