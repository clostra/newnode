//
//  ViewController.swift
//  NewNode VPN
//
//  Created by Gregory Hazel on 7/9/19.
//  Copyright © 2019 Clostra. All rights reserved.
//

import os.log
import UIKit

extension ViewController: TunnelManagerDelegate {
    func tunnelDidChangeState(_ state: TunnelManagerState) {
        update(for: state)
    }
}

class ViewController: UIViewController {
    
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
    let wormhole = MMWormhole(applicationGroupIdentifier: "group.com.newnode.vpn", optionalDirectory: nil)
    
    private lazy var tunnelManager = TunnelManagerImpl(delegate: self)
    
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

        updateLayout(on: toggleState, animated: false)
        
        wormhole.listenForMessage(withIdentifier: "DisplayStats", listener: { (message) -> Void in
            if let o = message as? NSDictionary, let direct = o["direct_bytes"] as? UInt64, let peer = o["peers_bytes"] as? UInt64 {
                self.updateStatistics(direct: direct, peer: peer)
            }
        })

        NotificationCenter.default.addObserver(self, selector:#selector(foreground), name:
                                                UIApplication.willEnterForegroundNotification, object: nil)

        update(for: .disconnected)
        if toggleState {
            stateChanged()
        }
    }

    func updateLayout(on: Bool, animated: Bool) {
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
    
    func stateChanged() {
        if toggleState {
            tunnelManager.connect()
        } else {
            tunnelManager.disconnect()
        }
    }
    
    @IBAction func toggleTapped() {
        let oldToggleState = toggleState
        os_log("didTapSwitch %@ -> %@", String(oldToggleState), String(!oldToggleState))
        toggleState = !oldToggleState
        stateChanged()
        updateLayout(on: toggleState, animated: true)
    }

    @objc func foreground() {
        stateChanged()
    }
    
    func update(for state: TunnelManagerState) {
        updateLayout(on: toggleState, animated: false)
        statusLabel.text = NSLocalizedString(state.rawValue, comment: "")
        
        if [.connecting, .disconnecting, .reasserting].contains(state) {
            spinner.startAnimating()
        } else {
            spinner.stopAnimating()
        }
    }
}
