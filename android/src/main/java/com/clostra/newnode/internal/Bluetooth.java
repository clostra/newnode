package com.clostra.newnode.internal;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.MacAddress;
import android.os.Handler;
import android.os.ParcelUuid;
import android.util.Log;
import androidx.annotation.RequiresApi;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.util.concurrent.ConcurrentHashMap;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;


@RequiresApi(29)
public class Bluetooth {
    static final String TAG = Bluetooth.class.getSimpleName();

    final static UUID serviceUUID = UUID.fromString("08076b03-983b-4154-93a5-4a6376b87993");
    final static String CBUUIDL2CAPPSMCharacteristicString = "ABDD3056-28FA-441D-A470-55A75A52553A";

    Map<String,DataOutputStream> peers = new ConcurrentHashMap<String,DataOutputStream>();
    BluetoothGattServer gattServer;

    AdvertiseCallback advertiseCallback = new AdvertiseCallback() {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect) {
            Log.d(TAG, "onStartSuccess settingsInEffect:" + settingsInEffect);
        }

        @Override
        public void onStartFailure(int errorCode) {
            Log.e(TAG, "onStartFailure errorCode:" + errorCode);
        }
    };

    ScanCallback scanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            BluetoothDevice device = result.getDevice();
            Log.d(TAG, "onScanResult " + device);

            ScanRecord record = result.getScanRecord();
            List<ParcelUuid> uuids = record.getServiceUuids();
            if (uuids == null || uuids.indexOf(new ParcelUuid(serviceUUID)) == -1) {
                return;
            }
            Log.d(TAG, "found NewNode service: " + device + " connecting...");
            try {
                device.connectGatt(NewNode.app(), false, gattCallback);
            } catch (SecurityException e) {
                Log.e(TAG, "scanCallback", e);
            }
        }

        @Override
        public void onBatchScanResults(List<ScanResult> results) {
            Log.d(TAG, "onBatchScanResults results:" + results);
            for (ScanResult result : results) {
                onScanResult(0, result);
            }
        }

        @Override
        public void onScanFailed(int errorCode) {
            Log.e(TAG, "onScanFailed errorCode:" + errorCode);
        }
    };

    BroadcastReceiver broadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.d(TAG, ""+intent + " " + intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_ON));
            if (!intent.getAction().equals(BluetoothAdapter.ACTION_STATE_CHANGED)) {
                return;
            }
            switch (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_ON)) {
            case BluetoothAdapter.STATE_ON:
                bluetoothOn();
                break;
            case BluetoothAdapter.STATE_TURNING_OFF:
            case BluetoothAdapter.STATE_OFF:
                stopScan();
                break;
            }
        }
    };

    BluetoothAdapter bluetoothAdapter() {
        BluetoothManager manager = (BluetoothManager) NewNode.app().getSystemService(Context.BLUETOOTH_SERVICE);
        return manager == null ? null : manager.getAdapter();
    }

    Bluetooth() {
        IntentFilter f = new IntentFilter();
        f.addAction(BluetoothAdapter.ACTION_STATE_CHANGED);
        NewNode.app().registerReceiver(broadcastReceiver, f);
    }

    void bluetoothOn() {
        try {
            if (!bluetoothAdapter().isEnabled()) {
                return;
            }
        } catch (SecurityException e) {
            Log.e(TAG, "bluetoothOn", e);
            return;
        }
        startServer();
        startScan();
    }

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
            Log.i(TAG, "onConnectionStateChange gatt:" + gatt.getDevice() + " status:" + status + " newState:" + newState);
            try {
                gatt.discoverServices();
            } catch (SecurityException e) {
                Log.e(TAG, "onConnectionStateChange", e);
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt gatt, int status) {
            Log.w(TAG, "onServicesDiscovered " + gatt.getDevice() + " status:" + status);
            if (status != BluetoothGatt.GATT_SUCCESS) {
                return;
            }
            BluetoothGattService service = gatt.getService(serviceUUID);
            Log.d(TAG, String.format("got gatt service:%s device:%s address:%s", service, gatt.getDevice(), gatt.getDevice().getAddress()));
            service.getCharacteristic(UUID.fromString(CBUUIDL2CAPPSMCharacteristicString));
        }

        @Override
        public void onMtuChanged(BluetoothGatt gatt, int mtu, int status) {
            Log.w(TAG, "onMtuChanged mtu:" + mtu + " status:" + status);
        }

        @Override
        public void onCharacteristicRead(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
            Log.w(TAG, "onCharacteristicRead " + gatt.getDevice() + " status:" + status);
            stopScan();
            int psm = characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_UINT16, 0);
            try {
                BluetoothSocket socket = gatt.getDevice().createInsecureL2capChannel(psm);
                socket.connect();
            } catch (IOException|SecurityException e) {
                Log.e(TAG, "connect", e);
            }
        }
    };

    static short ntohs(short v) {
        return (short)(((v & 0xff00) >> 8) | ((v & 0X00FF) << 8));
    }

    public void tryStartServer() throws IOException {
        BluetoothServerSocket serverSocket2 = null;
        try {
            serverSocket2 = bluetoothAdapter().listenUsingInsecureL2capChannel();
        } catch (SecurityException e) {
            Log.e(TAG, "tryStartServer", e);
            return;
        }
        final BluetoothServerSocket serverSocket = serverSocket2;
        Log.w(TAG, "serverSocket " + serverSocket);
        new Thread(){public void run() {
            for (;;) {
                BluetoothSocket socket2 = null;
                try {
                    socket2 = serverSocket.accept();
                } catch (IOException e) {
                    Log.e(TAG, "serverSocketThread", e);
                    break;
                }
                final BluetoothSocket socket = socket2;
                Log.w(TAG, "socket " + socket);

                final String address = socket.getRemoteDevice().getAddress().toLowerCase();
                final byte[] endpoint = stringToMac(address);
                Log.d(TAG, "address: " + address);

                new Thread(){public void run() {
                    try {
                        NewNode.addEndpoint(endpoint);
                        peers.put(address, new DataOutputStream(new BufferedOutputStream(socket.getOutputStream())));
                        DataInputStream stream = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                        for (;;) {
                            short lenthPrefix = ntohs(stream.readShort());
                            //Log.d(TAG, "in lenthPrefix:" + lenthPrefix + " address:" + address);
                            byte[] buf = new byte[lenthPrefix];
                            stream.readFully(buf);
                            NewNode.packetReceived(buf, endpoint);
                        }
                    } catch (IOException e) {
                        Log.e(TAG, "readThread", e);
                        peers.remove(address);
                        NewNode.removeEndpoint(endpoint);
                    }
                }}.start();
            }
        }}.start();

        AdvertiseSettings.Builder settingsBuilder = new AdvertiseSettings.Builder();
        settingsBuilder.setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER);
        settingsBuilder.setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH);
        settingsBuilder.setConnectable(true);

        AdvertiseData.Builder advertiseDataBuilder = new AdvertiseData.Builder();
        advertiseDataBuilder.addServiceUuid(new ParcelUuid(serviceUUID));

        AdvertiseData.Builder scanResponseBuilder = new AdvertiseData.Builder();
        scanResponseBuilder.addServiceUuid(new ParcelUuid(serviceUUID));

        BluetoothLeAdvertiser advertiser = bluetoothAdapter().getBluetoothLeAdvertiser();
        try {
            advertiser.startAdvertising(settingsBuilder.build(), advertiseDataBuilder.build(),
                                        scanResponseBuilder.build(), advertiseCallback);
        } catch (SecurityException e) {
            Log.e(TAG, "startAdvertising", e);
        }

        BluetoothGattCharacteristic l2cap = new BluetoothGattCharacteristic(UUID.fromString(CBUUIDL2CAPPSMCharacteristicString),
                                                                            BluetoothGattCharacteristic.PROPERTY_READ,
                                                                            BluetoothGattCharacteristic.PERMISSION_READ);
        l2cap.setValue(serverSocket.getPsm(), BluetoothGattCharacteristic.FORMAT_UINT16, 0);
        BluetoothGattService service = new BluetoothGattService(serviceUUID, BluetoothGattService.SERVICE_TYPE_PRIMARY);
        service.addCharacteristic(l2cap);
        BluetoothManager manager = (BluetoothManager) NewNode.app().getSystemService(Context.BLUETOOTH_SERVICE);
        try {
            gattServer = manager.openGattServer(NewNode.app(), new BluetoothGattServerCallback() {
                @Override
                public void onConnectionStateChange(BluetoothDevice device, int status, int newState) {
                    Log.i(TAG, "onConnectionStateChange device:" + device + " status:" + status + " newState:" + newState);
                    if (peers.size() == 0) {
                        startScan();
                    }
                }

                @Override
                public void onCharacteristicReadRequest(BluetoothDevice device, int requestId, int offset, BluetoothGattCharacteristic characteristic) {
                    Log.i(TAG, "onCharacteristicReadRequest");
                    gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, characteristic.getValue());
                }
            });
            gattServer.addService(service);
        } catch (SecurityException e) {
            Log.e(TAG, "openGattServer", e);
        }
    }

    public void startServer() {
        try {
            tryStartServer();
        } catch (Exception e) {
            Log.e(TAG, "startServer", e);
        }
    }

    UUID getUuidFromByteArray(byte[] data, int pos, int scanDirection) {
        int[] i = {4,2,2,2,6};
        StringBuilder uuid = new StringBuilder();
        for (int n :i) {
            for (int j=0;j<n;j++) {
                int q = (data[pos] & 0xf0) >> 4;
                uuid.append((char)(q<10 ? q+'0' : q+'a'-10));
                q = data[pos] & 0x0f;
                uuid.append((char)(q<10 ? q+'0' : q+'a'-10));
                pos += scanDirection;
            }
            uuid.append("-");
        }
        return UUID.fromString(uuid.deleteCharAt(uuid.length()-1).toString());
    }

    public void startScan() {
        Log.d(TAG, "startScan");

        ScanFilter.Builder serviceScanBuilder = new ScanFilter.Builder();
        serviceScanBuilder.setServiceUuid(new ParcelUuid(serviceUUID));

        List<ScanFilter> filters = Arrays.asList(serviceScanBuilder.build());

        ScanSettings.Builder settingsBuilder = new ScanSettings.Builder();
        settingsBuilder.setScanMode(ScanSettings.SCAN_MODE_LOW_POWER);

        try {
            bluetoothAdapter().getBluetoothLeScanner().startScan(filters, settingsBuilder.build(), scanCallback);
        } catch (SecurityException e) {
            Log.e(TAG, "startScan", e);
        }
    }

    public void stopAdvertising() {
        Log.d(TAG, "stopAdvertising");
        if (bluetoothAdapter().getBluetoothLeAdvertiser() != null) {
            try {
                bluetoothAdapter().getBluetoothLeAdvertiser().stopAdvertising(advertiseCallback);
            } catch (SecurityException e) {
                Log.e(TAG, "stopAdvertising", e);
            }
        }
    }

    public void stopScan() {
        Log.d(TAG, "stopScan");
        if (bluetoothAdapter().getBluetoothLeScanner() != null) {
            try {
                bluetoothAdapter().getBluetoothLeScanner().stopScan(scanCallback);
            } catch (SecurityException e) {
                Log.e(TAG, "stopScan", e);
            }
        }
    }

    byte[] stringToMac(String s) {
        return MacAddress.fromString(s).toByteArray();
    }

    String endpointToString(byte[] mac) {
        StringBuilder sb = new StringBuilder("00:11:22:33:44:55".length());
        for (int i = 0; i < 6; i++) {
            byte b = mac[i];
            if (sb.length() > 0)
                sb.append(':');
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    void sendPacket(byte[] packet, byte[] endpoint) {
        String address = endpointToString(endpoint);
        DataOutputStream stream = peers.get(address);
        if (stream == null) {
            Log.d(TAG, "endpoint not found: " + address);
            return;
        }
        //Log.d(TAG, "out lenthPrefix:" + packet.length + " address:" + address);
        short lenthPrefix = ntohs((short)packet.length);
        try {
            stream.writeShort(lenthPrefix);
            stream.write(packet, 0, packet.length);
            stream.flush();
        } catch (IOException e) {
            Log.e(TAG, "sendPacket", e);
        }
    }
}
