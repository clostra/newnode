package com.clostra.newnode.vpn;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

public class InfoFragment extends Fragment {
    public InfoFragment() {
        super(R.layout.info_fragment);
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {

        View view = inflater.inflate(R.layout.info_fragment, container, false);

        ImageButton close = view.findViewById(R.id.info_close_button);
        close.setOnClickListener(v -> getParentFragmentManager().beginTransaction().remove(this).commit());

        return view;
    }
}
