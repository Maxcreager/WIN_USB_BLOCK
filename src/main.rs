use iced::{
    widget::{button, Button, Column, Container, Row, Text},
    Alignment, executor, Application, Command, Element, Length, Settings, Theme,
    alignment::Horizontal,
};
use iced::theme;
use std::ffi::CStr;
use std::ptr;
use std::process::Command as SysCommand;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use winapi::shared::guiddef::GUID;
use winapi::um::winnt::HANDLE;
use winapi::um::setupapi::{
    SetupDiEnumDeviceInfo, SetupDiGetClassDevsA, SetupDiGetDeviceInstanceIdA,
    SetupDiDestroyDeviceInfoList, SP_DEVINFO_DATA, DIGCF_PRESENT, DIGCF_DEVICEINTERFACE,
};
use winapi::um::fileapi::{GetLogicalDrives, GetDriveTypeW};
use winapi::um::winbase::{DRIVE_REMOVABLE, DRIVE_FIXED};

const GUID_DEVINTERFACE_DISK: GUID = GUID {
    Data1: 0x53f56307,
    Data2: 0xb6bf,
    Data3: 0x11d0,
    Data4: [0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b],
};

const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

#[derive(Default)]
struct USBBlockerApp {
    devices: Vec<Device>,
    block_states: Vec<button::State>,
    test_states: Vec<button::State>,
}

#[derive(Debug, Clone)]
enum Message {
    ToggleBlock(usize),
    TestBlock(usize),
    DevicesListed(Vec<Device>),
    ActionConfirmed(String),
}

#[derive(Debug, Clone)]
struct Device {
    id: String,
    name: String,
    is_blocked: bool,
    drive_letter: Option<String>,
}

impl Application for USBBlockerApp {
    type Executor = executor::Default;
    type Message = Message;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Self::Message>) {
        let app = USBBlockerApp::default();
        (app, Command::perform(list_usb_devices(), Message::DevicesListed))
    }

    fn title(&self) -> String {
        String::from("USB Write Blocker")
    }

    type Theme = Theme;

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::ToggleBlock(index) => {
                let device = &self.devices[index];
                let action = if device.is_blocked {
                    unblock_usb_write(&device.id);
                    "unblocked"
                } else {
                    block_usb_write(&device.id);
                    "blocked"
                };
                let device_name = device.name.clone();
                self.devices[index].is_blocked = !device.is_blocked;
                Command::perform(
                    async move { format!("Device {} has been {}", device_name, action) },
                    Message::ActionConfirmed,
                )
            }
            Message::TestBlock(index) => {
                let device = &self.devices[index];
                let drive_letter = device.drive_letter.clone().unwrap_or_default();
                let test_result = test_block(&drive_letter);
                let device_name = device.name.clone();
                Command::perform(
                    async move { format!("Device {} test: {}", device_name, test_result) },
                    Message::ActionConfirmed,
                )
            }
            Message::DevicesListed(devices) => {
                self.block_states = devices.iter().map(|_| button::State::new()).collect();
                self.test_states = devices.iter().map(|_| button::State::new()).collect();
                self.devices = devices;
                Command::none()
            }
            Message::ActionConfirmed(message) => {
                println!("{}", message); // Replace with a modal dialog in the GUI
                Command::none()
            }
        }
    }

    fn view(&self) -> Element<Self::Message> {
        let scsi_devices: Vec<_> = self.devices.iter().enumerate().filter(|(_, device)| device.id.contains("SCSI")).collect();
        let usb_devices: Vec<_> = self.devices.iter().enumerate().filter(|(_, device)| device.id.contains("USB")).collect();

        let scsi_section = scsi_devices.iter().fold(Column::new().spacing(20).padding(20), |column, (index, device)| {
            let button_text = if device.is_blocked { "Unblock" } else { "Block" };
            let status_text = if device.is_blocked { "Blocked" } else { "Unblocked" };
            let drive_letter = device.drive_letter.as_deref().unwrap_or("");
            column.push(
                Row::new()
                    .spacing(20)
                    .align_items(Alignment::Center)
                    .push(Text::new(&device.name).width(Length::Fill))
                    .push(Text::new(drive_letter).width(Length::Shrink))
                    .push(Text::new(status_text).width(Length::Shrink))
                    .push(
                        Button::new(Text::new(button_text))
                            .on_press(Message::ToggleBlock(*index))
                            .width(Length::Fixed(80.0)),
                    )
                    .push(
                        Button::new(Text::new("Test"))
                            .on_press(Message::TestBlock(*index))
                            .width(Length::Fixed(80.0)),
                    ),
            )
        });

        let usb_section = usb_devices.iter().fold(Column::new().spacing(20).padding(20), |column, (index, device)| {
            let button_text = if device.is_blocked { "Unblock" } else { "Block" };
            let status_text = if device.is_blocked { "Blocked" } else { "Unblocked" };
            let drive_letter = device.drive_letter.as_deref().unwrap_or("");
            column.push(
                Row::new()
                    .spacing(20)
                    .align_items(Alignment::Center)
                    .push(Text::new(&device.name).width(Length::Fill))
                    .push(Text::new(drive_letter).width(Length::Shrink))
                    .push(Text::new(status_text).width(Length::Shrink))
                    .push(
                        Button::new(Text::new(button_text))
                            .on_press(Message::ToggleBlock(*index))
                            .width(Length::Fixed(80.0)),
                    )
                    .push(
                        Button::new(Text::new("Test"))
                            .on_press(Message::TestBlock(*index))
                            .width(Length::Fixed(80.0)),
                    ),
            )
        });

        let title = Text::new("USB Write Blocker")
            .size(40)
            .horizontal_alignment(Horizontal::Center);

        let scsi_title = Text::new("SCSI Devices")
            .size(30)
            .horizontal_alignment(Horizontal::Center);

        let usb_title = Text::new("USB Devices")
            .size(30)
            .horizontal_alignment(Horizontal::Center);

        let content = Column::new()
            .push(title)
            .push(scsi_title)
            .push(scsi_section)
            .push(usb_title)
            .push(usb_section)
            .align_items(Alignment::Center)
            .spacing(20)
            .padding(20);

        Container::new(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .style(theme::Container::default())
            .into()
    }
}

async fn list_usb_devices() -> Vec<Device> {
    let mut devices = Vec::new();
    let hdevinfo = unsafe {
        SetupDiGetClassDevsA(
            &GUID_DEVINTERFACE_DISK,
            ptr::null_mut(),
            ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };

    if hdevinfo != INVALID_HANDLE_VALUE {
        let mut devinfo_data: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
        devinfo_data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;

        let mut index = 0;
        while unsafe { SetupDiEnumDeviceInfo(hdevinfo, index, &mut devinfo_data) != 0 } {
            let mut buffer: [u8; 256] = [0; 256];
            unsafe {
                SetupDiGetDeviceInstanceIdA(
                    hdevinfo,
                    &mut devinfo_data,
                    buffer.as_mut_ptr() as *mut i8,
                    buffer.len() as u32,
                    ptr::null_mut(),
                );
            }

            let device_id = unsafe { CStr::from_ptr(buffer.as_ptr() as *const i8) };
            let device_id_str = device_id.to_string_lossy().into_owned();
            let is_blocked = is_usb_write_blocked(&device_id_str);
            let drive_letter = get_drive_letter(&device_id_str);

            devices.push(Device {
                id: device_id_str.clone(),
                name: device_id_str.clone(),
                is_blocked,
                drive_letter,
            });

            index += 1;
        }

        unsafe {
            SetupDiDestroyDeviceInfoList(hdevinfo);
        }
    }

    devices
}

fn get_drive_letter(device_id: &str) -> Option<String> {
    let mut drive_letters = HashMap::new();

    unsafe {
        let drives = GetLogicalDrives();
        for i in 0..26 {
            if drives & (1 << i) != 0 {
                let drive_letter = format!("{}:", (b'A' + i) as char);
                let drive_type = GetDriveTypeW(format!("{}\\", drive_letter).encode_utf16().collect::<Vec<u16>>().as_ptr());
                if drive_type == DRIVE_REMOVABLE || drive_type == DRIVE_FIXED {
                    drive_letters.insert(drive_letter.clone(), drive_letter);
                }
            }
        }
    }

    for (letter, _) in drive_letters {
        if device_id.contains(&letter) {
            return Some(letter);
        }
    }

    None
}

fn is_usb_write_blocked(device_id: &str) -> bool {
    let output = SysCommand::new("reg")
        .args(&[
            "query",
            &format!(
                r#"HKLM\SYSTEM\CurrentControlSet\Enum\{}\Device Parameters"#,
                device_id
            ),
            "/v",
            "WriteProtect",
        ])
        .output()
        .expect("Failed to query registry");

    let output_str = String::from_utf8_lossy(&output.stdout);
    output_str.contains("0x1")
}

fn block_usb_write(device_id: &str) {
    let command = format!(
        r#"reg add "HKLM\SYSTEM\CurrentControlSet\Enum\{}\Device Parameters" /v WriteProtect /t REG_DWORD /d 1 /f"#,
        device_id
    );
    SysCommand::new("cmd")
        .args(&["/C", &command])
        .output()
        .expect("Failed to block write access");
}

fn unblock_usb_write(device_id: &str) {
    let command = format!(
        r#"reg add "HKLM\SYSTEM\CurrentControlSet\Enum\{}\Device Parameters" /v WriteProtect /t REG_DWORD /d 0 /f"#,
        device_id
    );
    SysCommand::new("cmd")
        .args(&["/C", &command])
        .output()
        .expect("Failed to unblock write access");
}

fn test_block(drive_letter: &str) -> String {
    let test_file_path = format!("{}\\test_write.txt", drive_letter);
    let result = OpenOptions::new().write(true).create(true).open(&test_file_path);

    match result {
        Ok(mut file) => {
            if let Err(_) = writeln!(file, "Test write to check if blocking works.") {
                fs::remove_file(&test_file_path).ok();
                "Failed to write (blocker works)".to_string()
            } else {
                fs::remove_file(&test_file_path).ok();
                "Write successful (blocker failed)".to_string()
            }
        }
        Err(_) => "Failed to open file (blocker works)".to_string(),
    }
}

fn main() -> iced::Result {
    USBBlockerApp::run(Settings {
        antialiasing: true,
        ..Settings::default()
    })
}
