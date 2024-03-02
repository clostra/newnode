//
//  NetworkExtension+NewNode.swift
//  NewNode VPN
//
//  Created by Anton Ilinykh on 02.01.2023.
//  Copyright © 2023 Clostra. All rights reserved.
//

import Foundation
import NetworkExtension
import os.log


extension NETunnelProviderManager {
    static func loadManager(completion: @escaping (Result<NETunnelProviderManager, Error>) -> Void) {
        loadAllFromPreferences { managers, error in
            guard let managers = managers else {
                let error = error ?? NSError(domain: "unknown error", code: 0)
                os_log("failed to load managers: %@", type: .error, error.localizedDescription)
                completion(.failure(error))
                return
            }

            if let manager = managers.first {
                completion(.success(manager))
            } else {
                let manager = NETunnelProviderManager()
                let providerProtocol = NETunnelProviderProtocol()
                providerProtocol.providerBundleIdentifier = "com.newnode.vpn.tunnel"
                providerProtocol.serverAddress = "NewNode"
                manager.protocolConfiguration = providerProtocol
                manager.isEnabled = true
                manager.localizedDescription = "NewNode"

                manager.saveToPreferences { error in
                    if let error = error {
                        os_log("failed to save to preferences: %@", type: .error, error.localizedDescription)
                        completion(.failure(error))
                        return
                    }
                    manager.loadFromPreferences { error in
                        if let error = error {
                            os_log("failed to load from preferences: %@", type: .error, error.localizedDescription)
                            completion(.failure(error))
                        } else {
                            completion(.success(manager))
                        }
                    }
                }
            }
        }
    }
}


extension NEVPNStatus {
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


extension NEVPNError {
    var description: String {
        switch code {
        case .configurationDisabled: return "configurationDisabled"
        case .configurationInvalid: return "configurationInvalid"
        case .configurationStale: return "configurationStale"
        case .configurationUnknown: return "configurationUnknown"
        case .connectionFailed: return "connectionFailed"
        case .configurationReadWriteFailed: return "configurationReadWriteFailed"
        @unknown default: return "unknown"
        }
    }
}
