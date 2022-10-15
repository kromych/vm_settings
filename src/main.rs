use anyhow::Result;
use windows::core::BSTR;
use windows::core::HSTRING;
use windows::Win32::Foundation::DISP_E_TYPEMISMATCH;
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
use windows::Win32::System::Wmi::WBEM_E_NOT_FOUND;
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

fn get_row_item(o: &IWbemClassObject, name: &str) -> Result<Option<String>> {
    let mut value: VARIANT = Default::default();
    let name_hstr = HSTRING::from(name);
    unsafe {
        if let Err(e) = o.Get(
            &name_hstr,
            0,
            &mut value,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) {
            if e.code().0 == WBEM_E_NOT_FOUND.0 {
                return Ok(None);
            } else {
                anyhow::bail!(e);
            }
        }

        let bstr = VarFormat(
            &value,
            None,
            VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
            VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
            0,
        );
        if let Err(e) = &bstr {
            if e.code().0 == DISP_E_TYPEMISMATCH.0 {
                return Ok(None);
            } else {
                anyhow::bail!(e.to_owned());
            }
        }

        VariantClear(&mut value)?;
        Ok(Some(String::from_utf16(bstr?.as_wide())?))
    }
}

trait WmiRowConstructable<T> {
    fn from_row(row: &IWbemClassObject) -> Result<T>;
    fn query_one(key: &str) -> String;
}

#[derive(Debug)]
#[allow(dead_code)]
struct HyperVVmSettings {
    virtual_system_identifier: Option<String>,
    configuration_data_root: Option<String>,
    configuration_file: Option<String>,
    firmware_file: Option<String>,
    firmware_parameters: Option<String>,
    guest_state_data_root: Option<String>,
    guest_state_file: Option<String>,
    guest_state_isolation_enabled: Option<String>,
    guest_state_isolation_type: Option<String>,
    is_saved: Option<String>,
    virtual_system_sub_type: Option<String>,
    secure_boot_enabled: Option<String>,
    turn_off_on_guest_restart: Option<String>,
}

impl WmiRowConstructable<HyperVVmSettings> for HyperVVmSettings {
    fn from_row(row: &IWbemClassObject) -> Result<HyperVVmSettings> {
        Ok(HyperVVmSettings {
            virtual_system_identifier: get_row_item(row, "VirtualSystemIdentifier")?,
            configuration_data_root: get_row_item(row, "ConfigurationDataRoot")?,
            configuration_file: get_row_item(row, "ConfigurationFile")?,
            firmware_file: get_row_item(row, "FirmwareFile")?,
            firmware_parameters: get_row_item(row, "FirmwareParameters")?,
            guest_state_data_root: get_row_item(row, "GuestStateDataRoot")?,
            guest_state_file: get_row_item(row, "GuestStateFile")?,
            guest_state_isolation_enabled: get_row_item(row, "GuestStateIsolationEnabled")?,
            guest_state_isolation_type: get_row_item(row, "GuestStateIsolationType")?,
            is_saved: get_row_item(row, "IsSaved")?,
            virtual_system_sub_type: get_row_item(row, "VirtualSystemSubType")?,
            secure_boot_enabled: get_row_item(row, "SecureBootEnabled")?,
            turn_off_on_guest_restart: get_row_item(row, "TurnOffOnGuestRestart")?,
        })
    }

    fn query_one(key: &str) -> String {
        format!("SELECT * FROM Msvm_VirtualSystemSettingData WHERE ElementName='{key}'")
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct HyperVVmStatus {
    available_requested_states: Option<String>,
    caption: Option<String>,
    communication_status: Option<String>,
    creation_class_name: Option<String>,
    dedicated: Option<String>,
    description: Option<String>,
    detailed_status: Option<String>,
    element_name: Option<String>,
    enabled_default: Option<String>,
    enabled_state: Option<String>,
    enhanced_session_mode_state: Option<String>,
    failed_over_replication_type: Option<String>,
    health_state: Option<String>,
    hw_threads_per_core_realized: Option<String>,
    identifying_descriptions: Option<String>,
    install_date: Option<String>,
    instance_id: Option<String>,
    last_application_consistent_replication_time: Option<String>,
    last_replication_time: Option<String>,
    last_replication_type: Option<String>,
    last_successful_backup_time: Option<String>,
    name: Option<String>,
    name_format: Option<String>,
    number_of_numa_nodes: Option<String>,
    on_time_in_milliseconds: Option<String>,
    operating_status: Option<String>,
    operational_status: Option<String>,
    other_dedicated_descriptions: Option<String>,
    other_enabled_state: Option<String>,
    other_identifying_info: Option<String>,
    power_management_capabilities: Option<String>,
    primary_owner_contact: Option<String>,
    primary_owner_name: Option<String>,
    primary_status: Option<String>,
    process_id: Option<String>,
    replication_health: Option<String>,
    replication_mode: Option<String>,
    replication_state: Option<String>,
    requested_state: Option<String>,
    reset_capability: Option<String>,
    roles: Option<String>,
    status: Option<String>,
    status_descriptions: Option<String>,
    time_of_last_configuration_change: Option<String>,
    time_of_last_state_change: Option<String>,
    transitioning_to_state: Option<String>,
}

impl WmiRowConstructable<HyperVVmStatus> for HyperVVmStatus {
    fn from_row(row: &IWbemClassObject) -> Result<HyperVVmStatus> {
        Ok(HyperVVmStatus {
            available_requested_states: get_row_item(row, "AvailableRequestedStates")?,
            caption: get_row_item(row, "Caption")?,
            communication_status: get_row_item(row, "CommunicationStatus")?,
            creation_class_name: get_row_item(row, "CreationClassName")?,
            dedicated: get_row_item(row, "Dedicated")?,
            description: get_row_item(row, "Description")?,
            detailed_status: get_row_item(row, "DetailedStatus")?,
            element_name: get_row_item(row, "ElementName")?,
            enabled_default: get_row_item(row, "EnabledDefault")?,
            enabled_state: get_row_item(row, "EnabledState")?,
            enhanced_session_mode_state: get_row_item(row, "EnhancedSessionModeState")?,
            failed_over_replication_type: get_row_item(row, "FailedOverReplicationType")?,
            health_state: get_row_item(row, "HealthState")?,
            hw_threads_per_core_realized: get_row_item(row, "HwThreadsPerCoreRealized")?,
            identifying_descriptions: get_row_item(row, "IdentifyingDescriptions")?,
            install_date: get_row_item(row, "InstallDate")?,
            instance_id: get_row_item(row, "InstanceID")?,
            last_application_consistent_replication_time: get_row_item(
                row,
                "LastApplicationConsistentReplicationTime",
            )?,
            last_replication_time: get_row_item(row, "LastReplicationTime")?,
            last_replication_type: get_row_item(row, "LastReplicationType")?,
            last_successful_backup_time: get_row_item(row, "LastSuccessfulBackupTime")?,
            name: get_row_item(row, "Name")?,
            name_format: get_row_item(row, "NameFormat")?,
            number_of_numa_nodes: get_row_item(row, "NumberOfNumaNodes")?,
            on_time_in_milliseconds: get_row_item(row, "OnTimeInMilliseconds")?,
            operating_status: get_row_item(row, "OperatingStatus")?,
            operational_status: get_row_item(row, "OperationalStatus")?,
            other_dedicated_descriptions: get_row_item(row, "OtherDedicatedDescriptions")?,
            other_enabled_state: get_row_item(row, "OtherEnabledState")?,
            other_identifying_info: get_row_item(row, "OtherIdentifyingInfo")?,
            power_management_capabilities: get_row_item(row, "PowerManagementCapabilities")?,
            primary_owner_contact: get_row_item(row, "PrimaryOwnerContact")?,
            primary_owner_name: get_row_item(row, "PrimaryOwnerName")?,
            primary_status: get_row_item(row, "PrimaryStatus")?,
            process_id: get_row_item(row, "ProcessID")?,
            replication_health: get_row_item(row, "ReplicationHealth")?,
            replication_mode: get_row_item(row, "ReplicationMode")?,
            replication_state: get_row_item(row, "ReplicationState")?,
            requested_state: get_row_item(row, "RequestedState")?,
            reset_capability: get_row_item(row, "ResetCapability")?,
            roles: get_row_item(row, "Roles")?,
            status: get_row_item(row, "Status")?,
            status_descriptions: get_row_item(row, "StatusDescriptions")?,
            time_of_last_configuration_change: get_row_item(row, "TimeOfLastConfigurationChange")?,
            time_of_last_state_change: get_row_item(row, "TimeOfLastStateChange")?,
            transitioning_to_state: get_row_item(row, "TransitioningToState")?,
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
    let settings = query_one::<HyperVVmSettings>(&server, "pico-linux")?;
    println!("{settings:#?}");

    let status = query_one::<HyperVVmStatus>(&server, "pico-linux")?;
    println!("{status:#?}");

    Ok(())
}
