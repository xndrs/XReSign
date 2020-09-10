//
//  ViewController.swift
//  XReSign
//
//  Copyright © 2019 xndrs. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {
    let kLastProvisioningPathKey = "kLastProvisioningPathKey"
    let kEntitlementsPathKey = "kEntitlementsPathKey"

    @IBOutlet var textFieldIpaPath: NSTextField!
    @IBOutlet var textFieldProvisioningPath: NSTextField!
    @IBOutlet var textFieldEntitlementsPath: NSTextField!

    @IBOutlet var textFieldBundleId: NSTextField!
    @IBOutlet var comboBoxKeychains: NSComboBox!
    @IBOutlet var comboBoxCertificates: NSComboBox!
    @IBOutlet var buttonChangeBundleId: NSButton!
    @IBOutlet var buttonResign: NSButton!
    @IBOutlet var progressIndicator: NSProgressIndicator!

    fileprivate var certificates: [String] = []
    fileprivate var keychains: [String: String] = [:]
    fileprivate var tempDir: String?

    // MARK: - Main

    override func viewDidLoad() {
        super.viewDidLoad()
        if let defaultProvisioning = UserDefaults.standard.string(forKey: kLastProvisioningPathKey) {
            textFieldProvisioningPath.stringValue = defaultProvisioning
        }
        if let defaultEntitlements = UserDefaults.standard.string(forKey: kEntitlementsPathKey) {
            textFieldEntitlementsPath.stringValue = defaultEntitlements
        }
        loadKeychains()
    }

    override var representedObject: Any? {
        didSet {
            // Update the view, if already loaded.
        }
    }

    // MARK: - Keychains

    private func loadKeychains() {
        DispatchQueue.global().async {
            let task: Process = Process()
            let pipe: Pipe = Pipe()

            task.launchPath = "/usr/bin/security"
            task.arguments = ["list-keychains"]
            task.standardOutput = pipe
            task.standardError = pipe

            let handle = pipe.fileHandleForReading
            task.launch()
            self.parseKeychainsFrom(data: handle.readDataToEndOfFile())
        }
    }

    private func parseKeychainsFrom(data: Data) {
        let buffer = String(data: data, encoding: String.Encoding.utf8)!
        var map: [String: String] = [:]
        let characterSet = NSMutableCharacterSet.whitespace()
        characterSet.addCharacters(in: "\"")

        buffer.enumerateLines { line, _ in
            let trimmed = line.trimmingCharacters(in: characterSet as CharacterSet)
            let name = (trimmed as NSString).lastPathComponent
            map[name] = trimmed
        }

        DispatchQueue.main.sync {
            self.keychains = map
            self.comboBoxKeychains.reloadData()
            // load default for login.keychain-db
            map.enumerated().forEach { arg0 in
                let (offset, (key, _)) = arg0
                if key.localizedStandardContains("login.") {
                    self.comboBoxKeychains.selectItem(at: offset)
                }
            }
        }
    }

    // MARK: - Certificates

    private func loadCertificatesFromKeychain(_ keychain: String) {
        DispatchQueue.global().async {
            let task: Process = Process()
            let pipe: Pipe = Pipe()

            task.launchPath = "/usr/bin/security"
            task.arguments = ["find-identity", "-v", "-p", "codesigning", keychain]
            task.standardOutput = pipe
            task.standardError = pipe

            let handle = pipe.fileHandleForReading
            task.launch()
            self.parseCertificatesFrom(data: handle.readDataToEndOfFile())
        }
    }

    private func parseCertificatesFrom(data: Data) {
        let buffer = String(data: data, encoding: String.Encoding.utf8)!
        var names: [String] = []

        buffer.enumerateLines { line, _ in
            // default output line format for security command:
            // 1) E00D4E3D3272ABB655CDE0C1CF53891210BAF4B8 "iPhone Developer: XXXXXXXXXX (YYYYYYYYYY)"
            let components = line.components(separatedBy: "\"")
            if components.count > 2 {
                let commonName = components[components.count - 2]
                names.append(commonName)
            }
        }

        names.sort(by: { $0 < $1 })
        DispatchQueue.main.sync {
            self.certificates.removeAll()
            self.certificates.append(contentsOf: names)
            self.comboBoxCertificates.deselectItem(at: self.comboBoxCertificates.indexOfSelectedItem)
            self.comboBoxCertificates.reloadData()
        }
    }

    private func organizationUnitFromCertificate(by name: String) -> String? {
        let query: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                    kSecAttrLabel as String: name,
                                    kSecReturnRef as String: kCFBooleanTrue!]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }
        let certificate = item as! SecCertificate

        let keys = [kSecOIDX509V1SubjectName] as CFArray
        guard let subjectValue = SecCertificateCopyValues(certificate, keys, nil) else {
            return nil
        }

        if let subjectDict = subjectValue as? [String: Any] {
            let rootDict = subjectDict["\(kSecOIDX509V1SubjectName)"] as? [String: Any]
            if let values = rootDict?["value"] as? [Any] {
                for value in values {
                    if let dict = value as? [String: Any] {
                        if let label = dict["label"] as? String, let value = dict["value"] as? String {
                            if label.compare("\(kSecOIDOrganizationalUnitName)") == .orderedSame {
                                return value
                            }
                        }
                    }
                }
            }
        }
        return nil
    }

    private func teamIdentifierFromProvisioning(path provisioningPath: String) -> String? {
        guard let launchPath = Bundle.main.path(forResource: "entitlements", ofType: "sh") else {
            showAlertWith(title: nil, message: "Can not find entitlements script to run", style: .critical)
            return nil
        }

        guard let _ = tempDir else {
            showAlertWith(title: nil, message: "Internal error. No temporary directory for script.", style: .critical)
            return nil
        }

        let task: Process = Process()
        let pipe: Pipe = Pipe()

        task.launchPath = "/bin/sh"
        task.arguments = [launchPath, provisioningPath, tempDir!]
        task.standardOutput = pipe
        task.standardError = pipe

        let handle = pipe.fileHandleForReading
        task.launch()

        let data = handle.readDataToEndOfFile()
        let buffer = String(data: data, encoding: String.Encoding.utf8)!

        if let _ = buffer.range(of: "SUCCESS") {
            let path = "\(tempDir!)/entitlements.plist"
            if FileManager.default.fileExists(atPath: path) {
                if let plist = NSDictionary(contentsOfFile: path) {
                    if let teamIdentifier = plist["com.apple.developer.team-identifier"] as? String {
                        return teamIdentifier
                    }
                }
            }
        }
        return nil
    }

    private func signIpaWith(path ipaPath: String, developer: String, provisioning: String, bundle: String?, entitlementsPath: String?) {
        guard let launchPath = Bundle.main.path(forResource: "xresign", ofType: "sh") else {
            showAlertWith(title: nil, message: "Can not find resign script to run", style: .critical)
            return
        }

        buttonResign.isEnabled = false
        progressIndicator.isHidden = false
        progressIndicator.startAnimation(nil)

        DispatchQueue.global().async {
            let task: Process = Process()
            let pipe: Pipe = Pipe()

            task.launchPath = "/bin/sh"
            task.arguments = [launchPath, "-s", ipaPath, "-c", developer, "-p", provisioning, "-b", bundle ?? "", "-e", entitlementsPath ?? ""]
            task.standardOutput = pipe
            task.standardError = pipe

            let handle = pipe.fileHandleForReading
            task.launch()

            let data = handle.readDataToEndOfFile()
            let buffer = String(data: data, encoding: String.Encoding.utf8)!
            print("\(buffer)")

            var success = false
            if let _ = buffer.range(of: "XReSign FINISHED") {
                success = true
            }

            DispatchQueue.main.async {
                self.buttonResign.isEnabled = true
                self.progressIndicator.stopAnimation(nil)
                self.progressIndicator.isHidden = true

                if success {
                    self.showAlertWith(title: nil, message: "Re-sign finished", style: .informational)
                } else {
                    self.showAlertWith(title: nil, message: "Failed to re-sign the app", style: .critical)
                }
            }
        }
    }

    // MARK: - Entitlements

    func codesignEntitlementsDataFromApp(bundlePath: String) -> Data? {
//          // get entitlements: codesign -d <AppBinary> --entitlements :-
        let codesignTask: Process = Process()
        let pipe: Pipe = Pipe()

        codesignTask.launchPath = "/usr/bin/codesign"
        codesignTask.standardOutput = pipe
//        codesignTask.standardError = pipe
        codesignTask.arguments = ["-d", bundlePath, "--entitlements", ":-"]

        codesignTask.launch()
        let pipeData = pipe.fileHandleForReading.readDataToEndOfFile()
        codesignTask.waitUntilExit()
        return pipeData
    }

    // MARK: - Actions

    @IBAction func actionBrowseIpa(_ sender: Any) {
        let openPanel = NSOpenPanel()
        openPanel.allowsMultipleSelection = false
        openPanel.canChooseDirectories = false
        openPanel.canCreateDirectories = false
        openPanel.canChooseFiles = true
        openPanel.allowedFileTypes = ["ipa", "IPA"]
        openPanel.begin { (result) -> Void in
            if result == .OK {
                self.textFieldIpaPath.stringValue = openPanel.url?.path ?? ""
            }
        }
    }

    @IBAction func actionGetEntitlements(_ sender: Any) {
        let openPanel = NSOpenPanel()
        openPanel.allowsMultipleSelection = false
        openPanel.canChooseDirectories = false
        openPanel.canCreateDirectories = false
        openPanel.canChooseFiles = true
        openPanel.allowedFileTypes = ["ipa", "mobileprovision"]
        openPanel.begin { (result) -> Void in
            if result == .OK {
                if let path = openPanel.url?.path {
                    handleSelectedFile(path: path)
                }
            }
        }

        func handleSelectedFile(path: String) {
            let filePath = path as NSString
            let ipaDir = URL(fileURLWithPath: path).deletingLastPathComponent().path as NSString
            let entitlementsDir = ipaDir.appendingPathComponent("entitlements") as NSString
            let entitlementsPath = entitlementsDir.appendingPathComponent("entitlements.plist")

            if !FileManager.default.fileExists(atPath: String(entitlementsDir)) {
                //            try? FileManager.default.removeItem(atPath: String(currentTempDirFolder))
                try? FileManager.default.createDirectory(atPath: String(entitlementsDir), withIntermediateDirectories: true, attributes: nil)
            }

            if filePath.pathExtension.lowercased() == "ipa" {
                var unzipTask: Process = Process()
                unzipTask.launchPath = "/usr/bin/unzip"

                unzipTask.arguments = ["-u", "-j", "-o", "-q", "-d", String(entitlementsDir), path, "Payload/*.app/embedded.mobileprovision", "Payload/*.app/Info.plist", "-x", "*/*/*/*"]

                unzipTask.launch()
                unzipTask.waitUntilExit()

                let plistPath = entitlementsDir.appendingPathComponent("Info.plist")
                guard let appPlist = try? Data(contentsOf: URL(fileURLWithPath: plistPath)) else {
                    return
                }
                guard let appPropertyList = try? PropertyListSerialization.propertyList(from: appPlist, options: PropertyListSerialization.ReadOptions(), format: nil) else {
                    return
                }
                guard let pListDict = appPropertyList as? Dictionary<String, AnyObject> else {
                    return
                }
                guard let bundleExecutable = pListDict["CFBundleExecutable"] as? String else {
                    return
                }
                let bundlePath = NSString("Payload/*.app/").appendingPathComponent(bundleExecutable)

                unzipTask = Process()
                unzipTask.launchPath = "/usr/bin/unzip"
                unzipTask.arguments = ["-u", "-j", "-o", "-q", "-d", String(entitlementsDir), path, bundlePath, "-x", "*/*/*/*"]
                unzipTask.launch()
                unzipTask.waitUntilExit()

                if let codesignEntitlementsData = codesignEntitlementsDataFromApp(bundlePath: entitlementsDir.appendingPathComponent(bundleExecutable)) {
                    // read the entitlements directly from the codesign output
                    guard let entitlements = try? PropertyListSerialization.propertyList(from: codesignEntitlementsData, options: PropertyListSerialization.ReadOptions(), format: nil) as? NSDictionary else {
                        return
                    }
                    if entitlements.write(toFile: entitlementsPath, atomically: true) {
                        showAlertWith(title: nil, message: String(format: "get entitlements to %@", entitlementsPath), style: .informational)
                        NSWorkspace.shared.openFile(entitlementsDir as String)
                    }
                } else {
                    // read the entitlements from the provisioning profile instead
                    guard let entitlements = pListDict["Entitlements"] as? NSDictionary else {
                        return
                    }
                    if entitlements.write(toFile: entitlementsPath, atomically: true) {
                        showAlertWith(title: nil, message: String(format: "get entitlements to %@", entitlementsPath), style: .informational)
                        NSWorkspace.shared.openFile(entitlementsDir as String)
                    }
                }
            } else if filePath.pathExtension.lowercased() == "mobileprovision" {
                guard let launchPath = Bundle.main.path(forResource: "entitlements", ofType: "sh") else {
                    showAlertWith(title: nil, message: "Can not find entitlements script to run", style: .critical)
                    return
                }

                DispatchQueue.global().async {
                    let task: Process = Process()
                    let pipe: Pipe = Pipe()

                    task.launchPath = "/bin/sh"
                    task.arguments = [launchPath, path, entitlementsDir as String]
                    task.standardOutput = pipe
                    task.standardError = pipe

                    let handle = pipe.fileHandleForReading
                    task.launch()

                    let data = handle.readDataToEndOfFile()
                    let buffer = String(data: data, encoding: String.Encoding.utf8)!
                    print("\(buffer)")

                    var success = false
                    if let _ = buffer.range(of: "SUCCESS") {
                        success = true
                    }
                    DispatchQueue.main.async {
                        if success {
                            self.showAlertWith(title: nil, message: String(format: "get entitlements to %@", entitlementsDir), style: .informational)
                            NSWorkspace.shared.openFile(entitlementsDir as String)
                        } else {
                            return
                        }
                    }
                }
                return
            } else {
                showAlertWith(title: nil, message: "Please select mobileprovision or IPA file", style: .critical)
            }
        }
    }

    @IBAction func actionBrowsEntitlements(_ sender: Any) {
        let openPanel = NSOpenPanel()
        openPanel.allowsMultipleSelection = false
        openPanel.canChooseDirectories = false
        openPanel.canCreateDirectories = false
        openPanel.canChooseFiles = true
        openPanel.allowedFileTypes = ["plist"]
        openPanel.begin { (result) -> Void in
            if result == .OK {
                self.textFieldEntitlementsPath.stringValue = openPanel.url?.path ?? ""
            }
        }
    }

    @IBAction func actionBrowseProvisioning(_ sender: Any) {
        let openPanel = NSOpenPanel()
        openPanel.allowsMultipleSelection = false
        openPanel.canChooseDirectories = false
        openPanel.canCreateDirectories = false
        openPanel.canChooseFiles = true
        openPanel.allowedFileTypes = ["mobileprovision"]
        openPanel.begin { (result) -> Void in
            if result == .OK {
                self.textFieldProvisioningPath.stringValue = openPanel.url?.path ?? ""
            }
        }
    }

    @IBAction func actionChangeBundleId(_ sender: Any) {
        textFieldBundleId.isEnabled = buttonChangeBundleId.state == .on
    }

    @IBAction func actionSign(_ sender: Any) {
        let ipaPath = textFieldIpaPath.stringValue
        let provisioningPath = textFieldProvisioningPath.stringValue
        let entitlementsPath = textFieldEntitlementsPath.stringValue

        let bundleId: String? = buttonChangeBundleId.state == .on ? textFieldBundleId.stringValue : nil
        let index = comboBoxCertificates.indexOfSelectedItem
        let certificateName: String? = index >= 0 ? certificates[index] : nil

        if ipaPath.isEmpty {
            showAlertWith(title: nil, message: "IPA file not selected", style: .critical)
            return
        }

        guard let commonName = certificateName else {
            showAlertWith(title: nil, message: "Signing certificate not selected", style: .critical)
            return
        }

        tempDir = URL(fileURLWithPath: ipaPath).deletingLastPathComponent().path
        tempDir?.append("/tmp")
        if let path = tempDir {
            try? FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: nil)
        }

        if !entitlementsPath.isEmpty {
            if !FileManager.default.fileExists(atPath: entitlementsPath) {
                showAlertWith(title: nil,
                              message: "Entitlements not exists!",
                              style: .critical)
                return
            }
        }
        UserDefaults.standard.setValue(entitlementsPath, forKey: kEntitlementsPathKey)

        // if there is a path to provisioning profile, check right pair with signing certificate
        if !provisioningPath.isEmpty {
            guard let organizationUnit = organizationUnitFromCertificate(by: commonName) else {
                showAlertWith(title: nil,
                              message: "Can not retrieve organization unit value for certificate \(commonName)",
                              style: .critical)
                return
            }
            if !FileManager.default.fileExists(atPath: provisioningPath) {
                showAlertWith(title: nil,
                              message: "Provisioning not exists!",
                              style: .critical)
                return
            }
            guard let teamIdentifier = teamIdentifierFromProvisioning(path: provisioningPath) else {
                showAlertWith(title: nil,
                              message: "Can not retrieve team identifier from provisioning profile",
                              style: .critical)
                return
            }

            if organizationUnit.compare(teamIdentifier) != .orderedSame {
                showAlertWith(title: nil,
                              message: "There is a problem!\n" +
                                  "Different team identifiers\n" +
                                  "Provisioing team identifier: \(teamIdentifier)\n" +
                                  "Certificate team identifier: \(organizationUnit)\n" +
                                  "Check it and select the right pair.",
                              style: .critical)
                return
            }
        }

        UserDefaults.standard.setValue(provisioningPath, forKey: kLastProvisioningPathKey)
        signIpaWith(path: ipaPath, developer: commonName, provisioning: provisioningPath, bundle: bundleId, entitlementsPath: entitlementsPath)
    }

    // MARK: - Alert

    private func showAlertWith(title: String?, message: String, style: NSAlert.Style) {
        let alert = NSAlert()
        alert.messageText = title ?? "XReSign"
        alert.informativeText = message
        alert.alertStyle = style
        alert.addButton(withTitle: "Close")
        if let window = NSApp.keyWindow {
            alert.beginSheetModal(for: window, completionHandler: nil)
        } else {
            alert.runModal()
        }
    }
}

// MARK: - NSComboBoxDelegate

extension ViewController: NSComboBoxDelegate {
    func comboBoxSelectionDidChange(_ notification: Notification) {
        if let comboBox = notification.object as? NSComboBox, comboBox === comboBoxKeychains {
            guard comboBox.indexOfSelectedItem < keychains.count else { return }
            loadCertificatesFromKeychain(Array(keychains.values)[comboBox.indexOfSelectedItem])
        }
    }
}

// MARK: - NSComboBoxDataSource

extension ViewController: NSComboBoxDataSource {
    func numberOfItems(in comboBox: NSComboBox) -> Int {
        if comboBox === comboBoxKeychains {
            return keychains.count
        } else if comboBox === comboBoxCertificates {
            return certificates.count
        }
        return 0
    }

    func comboBox(_ comboBox: NSComboBox, objectValueForItemAt index: Int) -> Any? {
        if comboBox === comboBoxKeychains {
            return Array(keychains.keys)[index]
        } else if comboBox === comboBoxCertificates {
            return certificates[index]
        }
        return nil
    }
}
