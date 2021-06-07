package com.clostra.newnode.vpn.statistics;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.fragment.app.Fragment;

import com.clostra.newnode.vpn.R;

import java.util.Calendar;

import static android.text.format.Formatter.formatShortFileSize;

public class StatisticsFragment extends Fragment {
    public StatisticsFragment() {
        super(R.layout.stats_fragment);
    }

    private View layout;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        layout = inflater.inflate(R.layout.stats_fragment, container, false);
        updateDisplayStats(0, 0);
        return layout;
    }

    @Override
    public void onResume() {
        super.onResume();
        LocalBroadcastManager locationBroadcastManager = LocalBroadcastManager.getInstance(getContext());
        IntentFilter intentFilter = new IntentFilter("com.clostra.newnode.DISPLAY_STATS");
        locationBroadcastManager.registerReceiver(displayStatsReceiver, intentFilter);
    }

    @Override
    public void onPause() {
        super.onPause();
        LocalBroadcastManager locationBroadcastManager = LocalBroadcastManager.getInstance(getContext());
        locationBroadcastManager.unregisterReceiver(displayStatsReceiver);
    }

    private final BroadcastReceiver displayStatsReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String type = intent.getStringExtra("EXTRA_SCOPE");
            long direct = intent.getLongExtra("EXTRA_DIRECT_BYTES", 0);
            long peers = intent.getLongExtra("EXTRA_PEERS_BYTES", 0);
            updateDisplayStats(direct, peers);
        }
    };

    private void updateDisplayStats(long direct, long peers) {
        ((TextView) layout.findViewById(R.id.stat_direct))
                .setText(getResources().getString(R.string.stat_direct, formatShortFileSize(getContext(), direct)));
        ((TextView) layout.findViewById(R.id.stat_peer))
                .setText(getResources().getString(R.string.stat_peer, formatShortFileSize(getContext(), peers)));
    }
}
