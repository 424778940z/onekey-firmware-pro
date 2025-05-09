/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>

#include "py/mphal.h"
#include "py/objstr.h"
#include "py/runtime.h"

#if MICROPY_PY_TREZORIO

#include <unistd.h>

#include "button.h"
#include "touch.h"
#include "usb.h"

bool local_interface_ready = false;

#define CHECK_PARAM_RANGE(value, minimum, maximum)  \
  if (value < minimum || value > maximum) {         \
    mp_raise_ValueError(#value " is out of range"); \
  }

// clang-format off
#include "modtrezorio-flash.h"
#include "modtrezorio-hid.h"
#include "modtrezorio-poll.h"
#include "modtrezorio-vcp.h"
#include "modtrezorio-webusb.h"
#include "modtrezorio-usb.h"
#include "modtrezorio-hwinfo.h"
#include "modtrezorio-ble.h"
#include "modtrezorio-camera.h"
#include "modtrezorio-fatfs.h"
#include "modtrezorio-fingerprint.h"
#include "modtrezorio-local.h"
#include "modtrezorio-motor.h"
#include "modtrezorio-nfc.h"
#include "modtrezorio-sbu.h"
#include "modtrezorio-sdcard.h"
#include "modtrezorio-spi.h"
// clang-format on

/// package: trezorio.__init__
/// from . import fatfs, sdcard

/// POLL_READ: int  # wait until interface is readable and return read data
/// POLL_WRITE: int  # wait until interface is writable
///
/// TOUCH: int  # interface id of the touch events
/// TOUCH_START: int  # event id of touch start event
/// TOUCH_MOVE: int  # event id of touch move event
/// TOUCH_END: int  # event id of touch end event

/// UART: int  # interface id of the uart events
/// USB_STATE: int  # interface id of the usb state events
/// LOCAL: int  # interface local

/// BUTTON: int  # interface id of button events
/// BUTTON_PRESSED: int  # button down event
/// BUTTON_RELEASED: int  # button up event
/// BUTTON_LEFT: int  # button number of left button
/// BUTTON_RIGHT: int  # button number of right button

/// SPI_FACE: int  # interface id of the spi events
/// SPI_FIDO_FACE: int  # interface id of the spi fido events

/// WireInterface = Union[HID, WebUSB, SPI]
/// USB_CHECK: int # interface id for check of USB data connection
/// FINGERPRINT_STATE: int # interface id of the fingerprint state events

STATIC const mp_rom_map_elem_t mp_module_trezorio_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_trezorio)},

    {MP_ROM_QSTR(MP_QSTR_fatfs), MP_ROM_PTR(&mod_trezorio_fatfs_module)},
    {MP_ROM_QSTR(MP_QSTR_SBU), MP_ROM_PTR(&mod_trezorio_SBU_type)},
    {MP_ROM_QSTR(MP_QSTR_sdcard), MP_ROM_PTR(&mod_trezorio_sdcard_module)},
    {MP_ROM_QSTR(MP_QSTR_camera), MP_ROM_PTR(&mod_trezorio_camera_module)},
    {MP_ROM_QSTR(MP_QSTR_fingerprint),
     MP_ROM_PTR(&mod_trezorio_fingerprint_module)},

    {MP_ROM_QSTR(MP_QSTR_TOUCH), MP_ROM_INT(TOUCH_IFACE)},
    {MP_ROM_QSTR(MP_QSTR_TOUCH_START), MP_ROM_INT((TOUCH_START >> 24) & 0xFFU)},
    {MP_ROM_QSTR(MP_QSTR_TOUCH_MOVE), MP_ROM_INT((TOUCH_MOVE >> 24) & 0xFFU)},
    {MP_ROM_QSTR(MP_QSTR_TOUCH_END), MP_ROM_INT((TOUCH_END >> 24) & 0xFFU)},

    {MP_ROM_QSTR(MP_QSTR_UART), MP_ROM_INT(UART_IFACE)},
    {MP_ROM_QSTR(MP_QSTR_USB_STATE), MP_ROM_INT(USB_STATE_IFACE)},
    {MP_ROM_QSTR(MP_QSTR_FINGERPRINT_STATE), MP_ROM_INT(FINGERPRINT_IFACE)},
    {MP_ROM_QSTR(MP_QSTR_MOTOR), MP_ROM_PTR(&mod_trezorio_MOTOR_module)},
    {MP_ROM_QSTR(MP_QSTR_nfc), MP_ROM_PTR(&mod_trezorio_NFC_module)},
    {MP_ROM_QSTR(MP_QSTR_hwinfo), MP_ROM_PTR(&mod_trezorio_hwinfo_module)},

    {MP_ROM_QSTR(MP_QSTR_FlashOTP), MP_ROM_PTR(&mod_trezorio_FlashOTP_type)},

    {MP_ROM_QSTR(MP_QSTR_USB), MP_ROM_PTR(&mod_trezorio_USB_type)},
    {MP_ROM_QSTR(MP_QSTR_HID), MP_ROM_PTR(&mod_trezorio_HID_type)},
    {MP_ROM_QSTR(MP_QSTR_VCP), MP_ROM_PTR(&mod_trezorio_VCP_type)},
    {MP_ROM_QSTR(MP_QSTR_WebUSB), MP_ROM_PTR(&mod_trezorio_WebUSB_type)},
    {MP_ROM_QSTR(MP_QSTR_SPI), MP_ROM_PTR(&mod_trezorio_SPI_type)},
    {MP_ROM_QSTR(MP_QSTR_BLE), MP_ROM_PTR(&mod_trezorio_BLE_type)},
    {MP_ROM_QSTR(MP_QSTR_poll), MP_ROM_PTR(&mod_trezorio_poll_obj)},
    {MP_ROM_QSTR(MP_QSTR_POLL_READ), MP_ROM_INT(POLL_READ)},
    {MP_ROM_QSTR(MP_QSTR_POLL_WRITE), MP_ROM_INT(POLL_WRITE)},

    {MP_ROM_QSTR(MP_QSTR_LOCAL), MP_ROM_INT(LOCAL_IFACE)},
    {MP_ROM_QSTR(MP_QSTR_LOCAL_CTL), MP_ROM_PTR(&mod_trezorio_LOCAL_CTL_type)},

    {MP_ROM_QSTR(MP_QSTR_USB_CHECK), MP_ROM_INT(USB_DATA_IFACE)},

    {MP_ROM_QSTR(MP_QSTR_SPI_FACE), MP_ROM_INT(SPI_IFACE)},
    {MP_ROM_QSTR(MP_QSTR_SPI_FIDO_FACE), MP_ROM_INT(SPI_FIDO_IFACE)},
};

STATIC MP_DEFINE_CONST_DICT(mp_module_trezorio_globals,
                            mp_module_trezorio_globals_table);

const mp_obj_module_t mp_module_trezorio = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t*)&mp_module_trezorio_globals,
};

MP_REGISTER_MODULE(MP_QSTR_trezorio, mp_module_trezorio, MICROPY_PY_TREZORIO);

#endif  // MICROPY_PY_TREZORIO
