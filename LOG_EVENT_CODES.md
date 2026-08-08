# ISEO Argo access-log event codes

`LogEntry.event_code` (UINT8) meanings, from ISEO Argo app v4.1.0 (`EN.json`, `Log_<n>`).

Available programmatically: `from .client import LOG_EVENT_DESCRIPTIONS, describe_event`
(`describe_event(code)` returns the text below, or `"Unknown event (<code>)"`).

| code | meaning |
|---:|---|
| 0 | Software Upgrade |
| 1 | New MASTER Set |
| 2 | New MASTER Level |
| 3 | Phone not Paired |
| 4 | Not in Memory |
| 5 | Wrong PIN |
| 6 | Battery Empty |
| 7 | Delayed Open |
| 8 | Door Open |
| 9 | Passage Mode ON |
| 10 | Passage Mode OFF |
| 11 | Block Standard User ON |
| 12 | Block Standard User OFF |
| 13 | Blocked User |
| 14 | User List clear |
| 15 | User Added |
| 16 | User Deleted |
| 17 | User Updated |
| 18 | Changed Bluetooth Advertising rate |
| 19 | Door Close |
| 20 | Delayed Close |
| 21 | Memory Full |
| 22 | Lock not open due to motor extra-current error |
| 23 | Lock not open due to sensor time-out error |
| 24 | Lock not open due to generic error |
| 25 | Lock not close due to motor extra-current error |
| 26 | Lock not close due to sensor time-out error |
| 27 | Lock not close due to generic error |
| 28 | Enter Programming Mode |
| 29 | Exit Programming Mode |
| 30 | Power ON reset |
| 31 | User blocked for Privacy ON |
| 32 | Open with Mechanical Key |
| 33 | Open with Internal Handle |
| 34 | Open with Mechanical Key |
| 35 | Lock bolts in half-way by handle |
| 36 | Lock bolts in half-way by key |
| 37 | Close by Handle |
| 38 | Close with Mechanical Key |
| 39 | Set Privacy ON |
| 40 | Set Privacy OFF |
| 41 | Power ON watchdog reset |
| 42 | Restore Default Doorlock Setting succesfull |
| 43 | Reset Doorlock to Factory mode succesfull |
| 44 | Open denied due to internal handle pressed |
| 45 | Open by remote opening button |
| 46 | Exchange of coded keys performed |
| 47 | Bluetooth signal power set to standard level |
| 48 | Bluetooth signal power set to level high |
| 49 | Bluetooth advertising rate set to standard level |
| 50 | Bluetooth advertising rate set to level high |
| 51 | Not yet valid |
| 52 | Expired |
| 53 | Out of Time Schedule |
| 54 | Functional Mode change |
| 55 | Device in software setup |
| 56 | Passage Mode Change |
| 57 | Communication error with electric lock actuator |
| 58 | Configuration changed |
| 59 | Door Close Light |
| 60 | Lithium backup battery OK |
| 61 | Lithium backup battery KO |
| 62 | OEM authentication error |
| 63 | Mains power restored |
| 64 | Mains power undervoltage |
| 65 | Single Action Change |
| 66 | Bootloader Update |
| 67 | Sensor Unstable |
| 68 | Authentication mismatch |
| 69 | Generic |
| 70 | Lock not close due to latch not out |
| 71 | Fingerprint stuck alert |
| 72 | RTC synchronization request |
| 73 | RTC synchronized |
| 74 | Fingerprint reader firmware updated |
| 75 | Opening with low battery |
| 76 | Closing with low battery |
| 77 | Fingerprint mismatch |
| 78 | Enter Master mode |
| 79 | Exit Master mode |
| 80 | Door Opening Timeout |
| 81 | Door Open Light |
| 82 | Smart Device Blocked |
| 83 | Smart Device Unblocked |
| 84 | Manual Sensor Calibration Trigger |
| 85 | Peripheral open request |
| 86 | Permission denied |
| 87 | Proxy Login request |
| 88 | Opening denied |
| 89 | Wrong password |
| 90 | Hardware fault |
| 91 | Internal handle pressed |
| 92 | Door contact not touching |
| 93 | Master Mode |
| 94 | Fingerprint self recovered |
| 95 | Device initialized |
| 96 | Device uninitialized |
| 97 | Bluetooth connection error |
| 98 | Fingerprint initialization error |
| 99 | Master card error |
| 100 | Bluetooth disabled |
| 101 | Bluetooth reboot |
| 102 | Mechanical key |
| 103 | Mechanical open |
| 104 | Door locked |
| 105 | Door locked out of frame |
| 106 | Lock not open due to mechanical block |
