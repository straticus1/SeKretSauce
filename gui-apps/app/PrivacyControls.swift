import AppKit
import AVFoundation
import Foundation

enum PrivacyDevice: String, CaseIterable, Identifiable {
    case camera
    case microphone

    var id: String { rawValue }

    var mediaType: AVMediaType {
        switch self {
        case .camera: return .video
        case .microphone: return .audio
        }
    }

    var settingsAnchor: String {
        switch self {
        case .camera: return "Privacy_Camera"
        case .microphone: return "Privacy_Microphone"
        }
    }
}

@MainActor
final class PrivacyControls: ObservableObject {
    @Published private(set) var cameraStatus = AVCaptureDevice.authorizationStatus(for: .video)
    @Published private(set) var microphoneStatus = AVCaptureDevice.authorizationStatus(for: .audio)

    func refresh() {
        cameraStatus = AVCaptureDevice.authorizationStatus(for: .video)
        microphoneStatus = AVCaptureDevice.authorizationStatus(for: .audio)
    }

    func status(for device: PrivacyDevice) -> AVAuthorizationStatus {
        switch device {
        case .camera: return cameraStatus
        case .microphone: return microphoneStatus
        }
    }

    func requestAccess(to device: PrivacyDevice) async {
        _ = await AVCaptureDevice.requestAccess(for: device.mediaType)
        refresh()
    }

    /// macOS does not expose a supported API that globally disables these
    /// devices. Revocation is intentionally handed to System Settings.
    func openPrivacySettings(for device: PrivacyDevice) {
        guard let url = URL(
            string: "x-apple.systempreferences:com.apple.preference.security?\(device.settingsAnchor)"
        ) else { return }
        NSWorkspace.shared.open(url)
    }
}
