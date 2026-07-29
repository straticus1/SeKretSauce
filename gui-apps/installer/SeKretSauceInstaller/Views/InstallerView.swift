import SwiftUI

struct InstallerView: View {
    @StateObject private var installer = InstallerManager()

    var body: some View {
        ZStack {
            // Background gradient
            LinearGradient(
                colors: [Color(hex: "1a1a2e"), Color(hex: "16213e")],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(spacing: 0) {
                // Header
                HeaderView()

                // Content based on current step
                Group {
                    switch installer.currentStep {
                    case .welcome:
                        WelcomeStepView()
                    case .license:
                        LicenseStepView()
                    case .configuration:
                        ConfigurationStepView()
                    case .installing:
                        InstallingStepView()
                    case .complete:
                        CompleteStepView()
                    case .error:
                        ErrorStepView()
                    }
                }
                .transition(.opacity.combined(with: .move(edge: .trailing)))

                Spacer()

                // Footer with navigation
                FooterView()
            }
        }
        .environmentObject(installer)
        .animation(.easeInOut(duration: 0.3), value: installer.currentStep)
    }
}

// MARK: - Header View

struct HeaderView: View {
    var body: some View {
        HStack {
            Image(systemName: "shield.checkered")
                .font(.system(size: 32))
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color(hex: "e94560"), Color(hex: "ff6b6b")],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )

            VStack(alignment: .leading, spacing: 2) {
                Text("SeKretSauce")
                    .font(.title)
                    .fontWeight(.bold)
                    .foregroundColor(.white)

                Text("Security Agent Installer")
                    .font(.subheadline)
                    .foregroundColor(.gray)
            }

            Spacer()
        }
        .padding(.horizontal, 30)
        .padding(.vertical, 20)
        .background(Color.black.opacity(0.2))
    }
}

// MARK: - Footer View

struct FooterView: View {
    @EnvironmentObject var installer: InstallerManager

    var body: some View {
        HStack {
            // Cancel button
            if installer.currentStep != .complete && installer.currentStep != .installing {
                Button("Cancel") {
                    NSApplication.shared.terminate(nil)
                }
                .buttonStyle(SecondaryButtonStyle())
            }

            Spacer()

            // Back button
            if installer.canGoBack {
                Button("Back") {
                    installer.goBack()
                }
                .buttonStyle(SecondaryButtonStyle())
            }

            // Next/Install/Done button
            if installer.currentStep == .complete {
                Button("Done") {
                    NSApplication.shared.terminate(nil)
                }
                .buttonStyle(PrimaryButtonStyle())
            } else if installer.currentStep == .configuration {
                Button("Install") {
                    installer.startInstallation()
                }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(!installer.canProceed)
            } else if installer.currentStep != .installing && installer.currentStep != .error {
                Button("Continue") {
                    installer.goNext()
                }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(!installer.canProceed)
            } else if installer.currentStep == .error {
                Button("Retry") {
                    installer.retry()
                }
                .buttonStyle(PrimaryButtonStyle())
            }
        }
        .padding(.horizontal, 30)
        .padding(.vertical, 20)
        .background(Color.black.opacity(0.2))
    }
}

// MARK: - Step Views

struct WelcomeStepView: View {
    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            Image(systemName: "lock.shield.fill")
                .font(.system(size: 80))
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color(hex: "e94560"), Color(hex: "ff6b6b")],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .shadow(color: Color(hex: "e94560").opacity(0.5), radius: 20)

            Text("Welcome to SeKretSauce")
                .font(.title)
                .fontWeight(.bold)
                .foregroundColor(.white)

            Text("This installer will set up the SeKretSauce Security Agent on your Mac. The agent provides:")
                .font(.body)
                .foregroundColor(.gray)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            VStack(alignment: .leading, spacing: 12) {
                FeatureRow(icon: "terminal", text: "Optional SSH output recording & monitoring")
                FeatureRow(icon: "network", text: "Tunnel detection (Cloudflare, ngrok, etc.)")
                FeatureRow(icon: "waveform.path.ecg", text: "Behavioral malware & ransomware detection")
                FeatureRow(icon: "doc.text.magnifyingglass", text: "Compliance audit logging")
            }
            .padding(.horizontal, 60)
            .padding(.top, 10)

            Spacer()
        }
    }
}

struct FeatureRow: View {
    let icon: String
    let text: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundColor(Color(hex: "e94560"))
                .frame(width: 24)

            Text(text)
                .foregroundColor(.white)
                .font(.callout)

            Spacer()
        }
    }
}

struct LicenseStepView: View {
    @EnvironmentObject var installer: InstallerManager

    var body: some View {
        VStack(spacing: 20) {
            Text("License Agreement")
                .font(.title2)
                .fontWeight(.semibold)
                .foregroundColor(.white)
                .padding(.top, 20)

            ScrollView {
                Text(licenseText)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(.white.opacity(0.8))
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(Color.black.opacity(0.3))
            .cornerRadius(8)
            .padding(.horizontal, 30)

            HStack {
                Toggle(isOn: $installer.acceptedLicense) {
                    Text("I accept the terms of this license agreement")
                        .foregroundColor(.white)
                        .font(.callout)
                }
                .toggleStyle(CheckboxToggleStyle())

                Spacer()
            }
            .padding(.horizontal, 30)
            .padding(.bottom, 10)
        }
    }

    private var licenseText: String {
        """
        SEKRETSAUCE SECURITY AGENT
        END USER LICENSE AGREEMENT

        Copyright © 2024. All rights reserved.

        TERMS AND CONDITIONS

        1. LICENSE GRANT
        This software is licensed, not sold. Subject to the terms
        of this Agreement, Licensor grants you a limited,
        non-exclusive, non-transferable license to install and
        use the Software.

        2. RESTRICTIONS
        You may not:
        - Modify, reverse engineer, or decompile the Software
        - Distribute, sublicense, or transfer the Software
        - Use the Software for any unlawful purpose

        3. DATA COLLECTION
        This software monitors system activity including:
        - Process execution and selected file changes
        - Tunnel-related process behavior
        - Optional SSH session output when explicitly enabled
        - Local security audit events

        All data is collected for security monitoring and
        compliance purposes.

        4. PRIVACY
        Data remains local by default. If an administrator
        explicitly configures a remote HTTPS service, audit
        events may be transmitted for analysis and storage.

        5. WARRANTY DISCLAIMER
        THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF
        ANY KIND.

        6. LIMITATION OF LIABILITY
        IN NO EVENT SHALL THE LICENSOR BE LIABLE FOR ANY
        INDIRECT, INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES.

        By clicking "I accept", you acknowledge that you have
        read and agree to these terms.
        """
    }
}

struct CheckboxToggleStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack {
            Image(systemName: configuration.isOn ? "checkmark.square.fill" : "square")
                .foregroundColor(configuration.isOn ? Color(hex: "e94560") : .gray)
                .font(.title3)
                .onTapGesture {
                    configuration.isOn.toggle()
                }

            configuration.label
        }
    }
}

struct ConfigurationStepView: View {
    var body: some View {
        VStack(spacing: 20) {
            Text("Protection Setup")
                .font(.title2)
                .fontWeight(.semibold)
                .foregroundColor(.white)
                .padding(.top, 20)

            VStack(alignment: .leading, spacing: 20) {
                Text("Local protection is enabled by default")
                    .font(.headline)
                    .foregroundColor(.white)

                FeatureRow(icon: "waveform.path.ecg", text: "Behavioral malware detection")
                FeatureRow(icon: "lock.doc", text: "Ransomware behavior containment")
                FeatureRow(icon: "terminal", text: "Process and tunnel behavior monitoring")
                FeatureRow(icon: "doc.text.magnifyingglass", text: "Private local audit logs")

                Text("Optional server credentials are configured after installation in a root-owned terminal. This keeps API keys out of process arguments, installer logs, and AppleScript.")
                    .font(.callout)
                    .foregroundColor(.gray)
                    .padding(.top, 8)
            }
            .padding(.horizontal, 30)

            Spacer()
        }
    }
}

struct DarkTextFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .padding(10)
            .background(Color.black.opacity(0.3))
            .cornerRadius(8)
            .foregroundColor(.white)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.gray.opacity(0.3), lineWidth: 1)
            )
    }
}

struct InstallingStepView: View {
    @EnvironmentObject var installer: InstallerManager

    var body: some View {
        VStack(spacing: 30) {
            Spacer()

            // Progress indicator
            ZStack {
                Circle()
                    .stroke(Color.gray.opacity(0.3), lineWidth: 4)
                    .frame(width: 100, height: 100)

                Circle()
                    .trim(from: 0, to: installer.progress)
                    .stroke(
                        LinearGradient(
                            colors: [Color(hex: "e94560"), Color(hex: "ff6b6b")],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        style: StrokeStyle(lineWidth: 4, lineCap: .round)
                    )
                    .frame(width: 100, height: 100)
                    .rotationEffect(.degrees(-90))
                    .animation(.easeInOut(duration: 0.3), value: installer.progress)

                Text("\(Int(installer.progress * 100))%")
                    .font(.title2)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
            }

            Text("Installing SeKretSauce...")
                .font(.title3)
                .fontWeight(.semibold)
                .foregroundColor(.white)

            Text(installer.statusMessage)
                .font(.callout)
                .foregroundColor(.gray)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            // Installation log
            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(installer.logMessages, id: \.self) { message in
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(Color(hex: "4ade80"))
                                .font(.caption)

                            Text(message)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.white.opacity(0.8))
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            }
            .frame(height: 100)
            .background(Color.black.opacity(0.3))
            .cornerRadius(8)
            .padding(.horizontal, 30)

            Spacer()
        }
    }
}

struct CompleteStepView: View {
    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 80))
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color(hex: "4ade80"), Color(hex: "22c55e")],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .shadow(color: Color(hex: "4ade80").opacity(0.5), radius: 20)

            Text("Installation Complete!")
                .font(.title)
                .fontWeight(.bold)
                .foregroundColor(.white)

            Text("SeKretSauce Security Agent has been successfully installed and is now running.")
                .font(.body)
                .foregroundColor(.gray)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            VStack(alignment: .leading, spacing: 12) {
                InfoRow(label: "Daemon Status:", value: "Running")
                InfoRow(label: "Log Location:", value: "/Library/Logs/SeKretSauce/")
                InfoRow(label: "Recordings:", value: "~/Library/Application Support/SeKretSauce/recordings/")
            }
            .padding()
            .background(Color.black.opacity(0.3))
            .cornerRadius(8)
            .padding(.horizontal, 30)

            Text("You may need to grant additional permissions in System Settings > Privacy & Security")
                .font(.caption)
                .foregroundColor(.orange)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Text("Optional remote setup:\nsudo '/Library/Application Support/SeKretSauce/sekretsauced' --setup")
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.gray)
                .multilineTextAlignment(.center)

            Spacer()
        }
    }
}

struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .foregroundColor(.gray)
                .font(.callout)

            Spacer()

            Text(value)
                .foregroundColor(.white)
                .font(.system(.callout, design: .monospaced))
        }
    }
}

struct ErrorStepView: View {
    @EnvironmentObject var installer: InstallerManager

    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            Image(systemName: "xmark.octagon.fill")
                .font(.system(size: 80))
                .foregroundColor(.red)
                .shadow(color: .red.opacity(0.5), radius: 20)

            Text("Installation Failed")
                .font(.title)
                .fontWeight(.bold)
                .foregroundColor(.white)

            Text(installer.errorMessage)
                .font(.body)
                .foregroundColor(.gray)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            if !installer.logMessages.isEmpty {
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(installer.logMessages, id: \.self) { message in
                            Text(message)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.white.opacity(0.8))
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                }
                .frame(height: 100)
                .background(Color.black.opacity(0.3))
                .cornerRadius(8)
                .padding(.horizontal, 30)
            }

            Spacer()
        }
    }
}

// MARK: - Button Styles

struct PrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .foregroundColor(.white)
            .padding(.horizontal, 24)
            .padding(.vertical, 10)
            .background(
                LinearGradient(
                    colors: isEnabled
                        ? [Color(hex: "e94560"), Color(hex: "c73659")]
                        : [Color.gray, Color.gray.opacity(0.8)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
            .cornerRadius(8)
            .scaleEffect(configuration.isPressed ? 0.95 : 1.0)
            .animation(.easeInOut(duration: 0.1), value: configuration.isPressed)
    }
}

struct SecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .foregroundColor(.white)
            .padding(.horizontal, 24)
            .padding(.vertical, 10)
            .background(Color.white.opacity(0.1))
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.white.opacity(0.3), lineWidth: 1)
            )
            .scaleEffect(configuration.isPressed ? 0.95 : 1.0)
            .animation(.easeInOut(duration: 0.1), value: configuration.isPressed)
    }
}

// MARK: - Color Extension

extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3: // RGB (12-bit)
            (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6: // RGB (24-bit)
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8: // ARGB (32-bit)
            (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (1, 1, 1, 0)
        }
        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: Double(a) / 255
        )
    }
}

#Preview {
    InstallerView()
        .frame(width: 600, height: 450)
}
