/* SPDX-License-Identifier: Apache-2.0 */
package org.amnezia.awg.backend;

import java.util.HashSet;
import java.util.Set;

/** Pure identity gate for the static Android service future. The test/clear
 * and publication effect happen under one lock, never as check-then-act.
 * Callbacks must only assign/complete the future or owner; no native close,
 * framework call, lifecycle-lock acquisition or waiting is allowed here.
 */
final class AwgServicePublication<S> {
    private S current;
    private long token;
    private final Set<Long> retired = new HashSet<>();

    synchronized boolean publish(S service,long identity,Runnable completeFuture) {
        if (service == null || identity == 0 || retired.contains(identity) ||
                (current != null && current != service)) return false;
        current=service; token=identity;
        completeFuture.run();
        return true;
    }
    synchronized boolean adopt(S service,long identity,Runnable setOwner) {
        if (current != service || token != identity || retired.contains(identity)) return false;
        setOwner.run();
        return true;
    }
    synchronized void retire(S service,long identity,Runnable resetFuture) {
        if (identity == 0) return;
        retired.add(identity);
        if (current == service && token == identity) {
            current=null; token=0;
            resetFuture.run();
        }
    }
}
