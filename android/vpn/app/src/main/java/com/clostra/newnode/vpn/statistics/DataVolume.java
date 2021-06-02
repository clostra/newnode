package com.clostra.newnode.vpn.statistics;

public class DataVolume {
    private final long myDirect;
    private final long myPeer;

    public DataVolume(long direct, long peer) {
        myDirect = direct;
        myPeer = peer;
    }

    public long getDirect() {
        return myDirect;
    }

    public long getPeer() {
        return myPeer;
    }
}
