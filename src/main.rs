use anyhow::Result;
use clap::Parser;
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

#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    about,
    long_about = "Prints some settings and some status data for a Hyper-V VM"
)]
struct Args {
    hyperv_vm_name: String,
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
                tracing::warn!("Column {name} not found in the result set");
                return Ok(None);
            } else {
                tracing::error!("Error {:#x} when retrieving column {name}", e.code().0);
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
                tracing::warn!("Column {name} couldn't be formatted as string");
                return Ok(None);
            } else {
                tracing::error!("Error {:#x} when formatting column {name}", e.code().0);
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
    pub virtual_system_identifier: Option<String>,
    pub configuration_data_root: Option<String>,
    pub configuration_file: Option<String>,
    pub firmware_file: Option<String>,
    pub firmware_parameters: Option<String>,
    pub guest_state_data_root: Option<String>,
    pub guest_state_file: Option<String>,
    pub guest_state_isolation_enabled: Option<String>,
    pub guest_state_isolation_type: Option<String>,
    pub is_saved: Option<String>,
    pub virtual_system_sub_type: Option<String>,
    pub secure_boot_enabled: Option<String>,
    pub turn_off_on_guest_restart: Option<String>,
    pub version: Option<String>,
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
            version: get_row_item(row, "Version")?,
        })
    }

    fn query_one(key: &str) -> String {
        format!("SELECT * FROM Msvm_VirtualSystemSettingData WHERE ElementName='{key}'")
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct HyperVVmStatus {
    pub communication_status: Option<String>,
    pub health_state: Option<String>,
    pub hw_threads_per_core_realized: Option<String>,
    pub install_date: Option<String>,
    pub name: Option<String>,
    pub number_of_numa_nodes: Option<String>,
    pub on_time_in_milliseconds: Option<String>,
    pub operating_status: Option<String>,
    pub power_management_capabilities: Option<String>,
    pub primary_status: Option<String>,
    pub process_id: Option<String>,
    pub reset_capability: Option<String>,
    pub status: Option<String>,
}

impl WmiRowConstructable<HyperVVmStatus> for HyperVVmStatus {
    fn from_row(row: &IWbemClassObject) -> Result<HyperVVmStatus> {
        Ok(HyperVVmStatus {
            communication_status: get_row_item(row, "CommunicationStatus")?,
            health_state: get_row_item(row, "HealthState")?,
            hw_threads_per_core_realized: get_row_item(row, "HwThreadsPerCoreRealized")?,
            install_date: get_row_item(row, "InstallDate")?,
            name: get_row_item(row, "Name")?,
            number_of_numa_nodes: get_row_item(row, "NumberOfNumaNodes")?,
            on_time_in_milliseconds: get_row_item(row, "OnTimeInMilliseconds")?,
            operating_status: get_row_item(row, "OperatingStatus")?,
            power_management_capabilities: get_row_item(row, "PowerManagementCapabilities")?,
            primary_status: get_row_item(row, "PrimaryStatus")?,
            process_id: get_row_item(row, "ProcessID")?,
            reset_capability: get_row_item(row, "ResetCapability")?,
            status: get_row_item(row, "Status")?,
        })
    }

    fn query_one(key: &str) -> String {
        format!("SELECT * FROM Msvm_ComputerSystem WHERE ElementName='{key}'")
    }
}

fn query_one<T>(server: &IWbemServices, vm_name: &str) -> Result<Option<T>>
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

        query.Next(-1, &mut row, &mut returned).and_then(|| {
            if let Some(row) = &row[0] {
                Ok(Some(T::from_row(row)?))
            } else {
                Ok(None)
            }
        })?
    }
}

fn main() -> Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();

    let args = Args::parse();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    init_com()?;

    let server = connect_hyperv_wmi()?;
    let settings = query_one::<HyperVVmSettings>(&server, &args.hyperv_vm_name)?;
    tracing::info!("Found: {settings:?}");

    let status = query_one::<HyperVVmStatus>(&server, &args.hyperv_vm_name)?;
    tracing::info!("Found: {status:?}");

    Ok(())
}
