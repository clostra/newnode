//
//  ViewController.swift
//  NewNode VPN
//
//  Created by Gregory Hazel on 7/9/19.
//  Copyright © 2019 Clostra. All rights reserved.
//

import os.log
import UIKit
import Network
import NetworkExtension

class ViewController: UIViewController, LLSwitchDelegate {

    @IBOutlet weak var toggle: LLSwitch!
    @IBOutlet weak var label: UILabel!
    @IBOutlet weak var spinner: UIActivityIndicatorView!
    let monitor = NWPathMonitor()
    
    override func viewDidLoad() {
        super.viewDidLoad()

        self.toggle.setOn(UserDefaults.standard.bool(forKey: "toggle"), animated: false)
        self.toggle.delegate = self

        monitor.pathUpdateHandler = { path in
            self.update()
        }
        monitor.start(queue: .main)

        NotificationCenter.default.addObserver(self, selector:#selector(foreground), name:
            UIApplication.willEnterForegroundNotification, object: nil)

        update()
        if UserDefaults.standard.bool(forKey: "toggle") {
            stateChanged()
        }
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    func waitForStop(_ manager: NETunnelProviderManager) {
        manager.loadFromPreferences(completionHandler: { (error: Error?) in
            self.update()
            if manager.connection.status == .disconnected {
                return
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                self.waitForStop(manager)
            }
        })
    }

    func enforceState(_ manager: NETunnelProviderManager) {
        os_log("manager.connection.status:%@ toggle:%@",
               String(manager.connection.status.rawValue), String(UserDefaults.standard.bool(forKey: "toggle")))
        if UserDefaults.standard.bool(forKey: "toggle") {
            do {
                os_log("starting...")
                try manager.connection.startVPNTunnel()
            } catch {
                os_log("Unexpected error %@", error.localizedDescription)
                manager.connection.stopVPNTunnel()
                self.waitForStop(manager)
            }
        } else {
            os_log("stopping...")
            manager.connection.stopVPNTunnel()
            self.waitForStop(manager)
        }
    }

    func stateChanged() {
        NETunnelProviderManager.loadAllFromPreferences { (managers: [NETunnelProviderManager]?, error: Error?) in
            guard let managers = managers else {
                os_log("loadAllFromPreferences %@", error?.localizedDescription ?? "")
                return
            }
            if managers.count == 0 {
                let manager = NETunnelProviderManager()
                let providerProtocol = NETunnelProviderProtocol()
                providerProtocol.providerBundleIdentifier = "com.newnode.vpn.tunnel"
                providerProtocol.serverAddress = "NewNode"
                manager.protocolConfiguration = providerProtocol
                manager.isEnabled = true
                manager.localizedDescription = "NewNode"
                
                manager.saveToPreferences(completionHandler: { (error: Error?) in
                    os_log("saveToPreferences %@", error?.localizedDescription ?? "")
                    manager.loadFromPreferences(completionHandler: { (error: Error?) in
                        os_log("loadFromPreferences %@", error?.localizedDescription ?? "")
                        self.enforceState(manager)
                    })
                })
            } else if managers.count > 0 {
                let manager = managers.first!
                self.enforceState(manager)
            }
            self.update()
        }
    }

    func didTap(_ llSwitch: LLSwitch) {
        os_log("didTapLLSwitch on:%@ changing to:%@",
               String(self.toggle.on), String(!self.toggle.on))
        UserDefaults.standard.set(!self.toggle.on, forKey: "toggle")
        stateChanged()
    }
    
    @objc func foreground() {
        stateChanged()
    }

    func update() {
        NETunnelProviderManager.loadAllFromPreferences { (managers: [NETunnelProviderManager]?, error: Error?) in
            guard let managers = managers else {
                os_log("loadAllFromPreferences %@", error?.localizedDescription ?? "")
                return
            }
            var status: NEVPNStatus = .disconnected
            if managers.count > 0 {
                let manager = managers.first!
                status = manager.connection.status
            }
            self.label.text = { switch status {
                case .invalid: return "Not Configured"
                case .disconnected: return "Not Connected"
                case .connecting: return "Connecting..."
                case .connected: return "Connected"
                case .reasserting: return "Reconnecting..."
                case .disconnecting: return "Disconnecting..."
                @unknown default: return "Unknown"
            }}()

            switch status {
            case .connecting: fallthrough
            case .reasserting: fallthrough
            case .disconnecting: self.spinner.startAnimating()
            case .invalid: fallthrough
            case .disconnected: fallthrough
            case .connected: fallthrough
            @unknown default: self.spinner.stopAnimating()
            }
        }
    }
}

