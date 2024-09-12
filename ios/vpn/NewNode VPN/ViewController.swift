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


private extension String {
    static let applicationGroupIdentifier = "group.com.newnode.vpn"
    static let wormholeStatisticMessageIdentifier = "DisplayStats"
    
    static let tunnelBundleIdentifier = "com.newnode.vpn.tunnel"
    static let tunnelServerAddress = "NewNode"
    static let tunnelLocalizedDescription = "NewNode"
}

final class ViewController: UIViewController {
    
    @IBOutlet var gradient: GradientView!
    @IBOutlet weak var powerButton: UIButton!
    @IBOutlet weak var infoButton: UIButton!
    @IBOutlet weak var spinner: SpinnerView!
    @IBOutlet weak var earthMap: UIImageView!
    @IBOutlet weak var cities: UIImageView!
    @IBOutlet weak var statusLabel: UILabel!
    @IBOutlet weak var hintLabel: UILabel!
    @IBOutlet weak var usageLabel: UILabel!
    @IBOutlet weak var logo: UIImageView!
    @IBOutlet var statTexts: [UILabel]!
    let monitor = NWPathMonitor()
    let wormhole = MMWormhole(applicationGroupIdentifier: .applicationGroupIdentifier, optionalDirectory: nil)
    
    var toggleState: Bool {
        get {
            return UserDefaults.standard.bool(forKey: "toggle")
        }
        set(newValue){
            UserDefaults.standard.set(newValue, forKey: "toggle")
        }
    }
    
    var isDarkMode: Bool {
        if #available(iOS 13.0, *) {
            return self.traitCollection.userInterfaceStyle == .dark
        }
        else {
            return false
        }
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        updateLayout(animated: false)
        
        monitor.pathUpdateHandler = { path in
            self.update()
        }
        monitor.start(queue: .main)

        wormhole.listenForMessage(withIdentifier: .wormholeStatisticMessageIdentifier, listener: { (message) -> Void in
            if let o = message as? NSDictionary, let direct = o["direct_bytes"] as? UInt64, let peer = o["peers_bytes"] as? UInt64 {
                self.updateStatistics(direct: direct, peer: peer)
            }
        })

        NotificationCenter.default.addObserver(self, selector:#selector(foreground), name:
                                                UIApplication.willEnterForegroundNotification, object: nil)

        update()
        if toggleState {
            stateChanged()
        }
    }

    func updateLayout(animated: Bool) {
        let on = toggleState
        spinner.alpha = 0.3
        let buttonImage = on ? UIImage(named: "power_button_on") : UIImage(named: "power_button_off")
        self.powerButton.setImage(buttonImage, for: .normal)
        let buttonPressedImage = on ? UIImage(named: "power_button_on_pressed") : UIImage(named: "power_button_off_pressed")
        self.powerButton.setImage(buttonPressedImage, for: .highlighted)
        
        gradient.startColor = on ? UIColor(named:"gradient_on1")! : UIColor(named:"gradient_off1")!
        gradient.endColor = on ? UIColor(named:"gradient_on2")! : UIColor(named:"gradient_off2")!
        
        hintLabel.text = NSLocalizedString(on ? "hint_connected" : "hint_disconnected", comment: "")
        
        let secondary_text_color = on ? UIColor(named:"usage_text_on")! : UIColor(named:"usage_text_off")!
        hintLabel.textColor = secondary_text_color
        usageLabel.textColor = secondary_text_color
        statTexts[0].textColor = secondary_text_color
        statTexts[1].textColor = secondary_text_color
        
        statusLabel.textColor = on ? UIColor(named:"status_text_on")! : UIColor(named:"status_text_off")!
        
        logo.image = on ? UIImage(named: "newnode_logo_on") : UIImage(named: "newnode_logo_off")
        
        let infoImage = on ? UIImage(named: "info_on") : UIImage(named: "info_off")
        infoButton.setImage(infoImage, for: .normal)
        
        if isDarkMode {
            earthMap.image =  UIImage(named: "earth_map_dark")
        }
        else {
            earthMap.image = on ? UIImage(named: "earth_map_blue") : UIImage(named: "earth_map_gray")
        }
        
        if animated {
            cities.alpha = on ? 0 : 1
            UIView.animate(withDuration: 1.8) {
                self.cities.alpha = on ? 1 : 0
            }
            
        }
        else {
            cities.alpha = on ? 1 : 0
        }
    }

    func updateStatistics(direct: UInt64, peer: UInt64) {
        let formatter = ByteCountFormatter()
        formatter.allowsNonnumericFormatting = false
        formatter.isAdaptive = true

        statTexts[0].text = NSLocalizedString("direct", comment: "") + formatter.string(fromByteCount: Int64(direct))
        statTexts[1].text = NSLocalizedString("peers", comment: "") + formatter.string(fromByteCount: Int64(peer))
    }
    
    @IBAction func infoTapped(_ sender: Any) {
        let storyboard = UIStoryboard(name: "Main", bundle: nil)
        let infoVC = storyboard.instantiateViewController(identifier: "InfoViewController")
        
        infoVC.modalPresentationStyle = .overCurrentContext
        infoVC.modalTransitionStyle = .crossDissolve
        present(infoVC, animated: true, completion: nil)
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
               String(manager.connection.status.rawValue), String(toggleState))
        if toggleState {
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
                providerProtocol.providerBundleIdentifier = .tunnelBundleIdentifier
                providerProtocol.serverAddress = .tunnelServerAddress
                manager.protocolConfiguration = providerProtocol
                manager.isEnabled = true
                manager.localizedDescription = .tunnelLocalizedDescription
                
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
    
    @IBAction func toggleTapped() {
        let oldToggleState = toggleState
        os_log("didTapSwitch %@ -> %@", String(oldToggleState), String(!oldToggleState))
        toggleState = !oldToggleState
        stateChanged()
        updateLayout(animated: true)
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
            
            self.updateLayout(animated: false)
            self.statusLabel.text = NSLocalizedString(status.description, comment: "")
            
            if status.isTransitional {
                self.spinner.startAnimating()
            } else {
                self.spinner.stopAnimating()
            }
        }
    }
}


private extension NEVPNStatus {
    var isTransitional: Bool {
        [.connecting, .reasserting, .disconnecting].contains(self)
    }
    
    var description: String {
        switch self {
        case .invalid: return "invalid"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "reconnecting"
        case .disconnecting: return "disconnecting"
        @unknown default: return ""
        }
    }
}
