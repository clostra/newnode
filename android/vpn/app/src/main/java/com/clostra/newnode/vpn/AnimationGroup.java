package com.clostra.newnode.vpn;

import android.animation.AnimatorInflater;
import android.animation.AnimatorSet;
import android.content.Context;
import android.view.View;

import androidx.annotation.AnimatorRes;

import java.util.ArrayList;

public class AnimationGroup {
    @AnimatorRes
    private final int forwardAnimatorId;
    @AnimatorRes private final int backwardAnimatorId;
    private final Context context;
    private final ArrayList<AnimatorSet> forwardAnimators = new ArrayList<>();
    private final ArrayList<AnimatorSet> backwardAnimators = new ArrayList<>();

    public AnimationGroup(Context context, @AnimatorRes int forwardAnimatorId, @AnimatorRes int backwardAnimatorId) {
        this.context = context;
        this.forwardAnimatorId = forwardAnimatorId;
        this.backwardAnimatorId = backwardAnimatorId;
    }

    public void addTarget(View target) {
        AnimatorSet forward = (AnimatorSet) AnimatorInflater.loadAnimator(context, forwardAnimatorId);
        forward.setTarget(target);
        forwardAnimators.add(forward);

        AnimatorSet backward = (AnimatorSet) AnimatorInflater.loadAnimator(context, backwardAnimatorId);
        backward.setTarget(target);
        backwardAnimators.add(backward);
    }

    public void forward() {
        forwardAnimators.forEach(AnimatorSet::start);
    }

    public void backward() {
        backwardAnimators.forEach(AnimatorSet::start);
    }
}
