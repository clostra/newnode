//
//  TunnelManager.swift
//  NewNode VPN
//
//  Created by Anton Ilinykh on 01.01.2023.
//  Copyright © 2023 Clostra. All rights reserved.
//

import Foundation
import NetworkExtension
import os.log

enum TunnelManagerState: String {
    case invalid
    case connecting
    case connected
    case reasserting
    case disconnecting
    case disconnected
}

protocol TunnelManagerDelegate {
    func tunnelDidChangeState(_ state: TunnelManagerState)
}

protocol TunnelManager {
    func connect()
    func disconnect()
}

final class TunnelManagerImpl: TunnelManager {
    private let delegate: TunnelManagerDelegate
    private var connection: NEVPNConnection?
    
    init(delegate: TunnelManagerDelegate) {
        self.delegate = delegate
        
        NotificationCenter.default.addObserver(forName: NSNotification.Name.NEVPNStatusDidChange, object: nil, queue: .main, using: { note in
            guard let session = note.object as? NETunnelProviderSession else {
                os_log("unexpected vpn status notification state", type: .error)
                return
            }
            os_log("connection state changed to %s", session.status.description)
            switch session.status {
            case .connecting:
                delegate.tunnelDidChangeState(.connecting)
            case .connected:
                delegate.tunnelDidChangeState(.connected)
            case .disconnecting:
                delegate.tunnelDidChangeState(.disconnecting)
            case .disconnected:
                delegate.tunnelDidChangeState(.disconnected)
            case .invalid:
                delegate.tunnelDidChangeState(.invalid)
            case .reasserting:
                delegate.tunnelDidChangeState(.reasserting)
            @unknown default:
                delegate.tunnelDidChangeState(.invalid)
            }
        })
    }

    func disconnect() {
        connection?.stopVPNTunnel()
    }
    
    func connect() {
        delegate.tunnelDidChangeState(.connecting)
        NETunnelProviderManager.loadManager { [weak self] result in
            switch(result) {
            case .success(let manager):
                do {
                    try manager.connection.startVPNTunnel()
                    self?.connection = manager.connection
                } catch {
                    /* The `confugarationDisabled` error ocurrs when the `manager`
                     * turns to `disabled` state. It may happen when user
                     * turn on another VPN or toggles the switch in settings
                     */
                    if let err = error as? NEVPNError, err.code == .configurationDisabled {
                        manager.isEnabled = true
                        manager.saveToPreferences() { error in
                            if let error = error {
                                os_log("failed to save to preferences: %@", type: .error, error.localizedDescription)
                            } else {
                                self?.connect()
                            }
                        }
                    }
                    os_log("failed to start vpn: %@", type: .error, error.localizedDescription)
                    self?.delegate.tunnelDidChangeState(.invalid)
                }
            case .failure(let error):
                os_log("failed to load manager: %@", type: .error, error.localizedDescription)
                self?.delegate.tunnelDidChangeState(.invalid)
            }
        }
    }
}
