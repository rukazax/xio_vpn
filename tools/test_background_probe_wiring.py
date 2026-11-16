"""Production entrypoint wiring assertions, complementing injected JVM checks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
KOTLIN = ROOT / 'app/android/app/src/main/kotlin/app/xio/xio'


class BackgroundProbeWiringTests(unittest.TestCase):
    def test_tile_and_restore_enter_actual_controller(self):
        self.assertIn('Intent(this,VpnControlService::class.java)', (KOTLIN / 'VpnTileService.kt').read_text())
        self.assertIn('Intent(this,VpnControlService::class.java).setAction("app.xio.RECONNECT")', (KOTLIN / 'XioVpnService.kt').read_text())

    def test_actual_controller_reads_strict_options_after_consent(self):
        text = (KOTLIN / 'VpnControlService.kt').read_text()
        parse = 'BackgroundVerificationOptions.fromPlanValue(plan.opt("siteCheckEnabled"))'
        self.assertIn(parse, text)
        self.assertLess(text.index('"consentRevision"'), text.index(parse))
        self.assertNotIn('optBoolean("siteCheckEnabled"', text)  # org.json coerces string true.
        self.assertIn('if(verification.siteCheckEnabled)', text)
        self.assertIn('site.protocol=="https"', text)

    def test_actual_candidate_uses_gate_between_native_connect_and_budget_fence(self):
        text = (KOTLIN / 'VpnControlService.kt').read_text()
        self.assertIn('verification.verify(started,attempt,', text)
        connect = text.index('Engine.connect(id,true,attempt,policy.toString(),roundId)')
        verify = text.index('verification.verify(started,attempt,', connect)
        fence = text.index('attempt.remainingMillis()', verify)
        self.assertLess(connect, verify)
        self.assertLess(verify, fence)
        self.assertEqual(text.count('ConnectionProbe.verify('), 1)
        self.assertIn('remaining -> ConnectionProbe.verify(checkNotNull(site),started,remaining)', text)
        self.assertIn('Engine.handshake()', text[verify:fence])
        self.assertIn('Thread.sleep(millis)', text[verify:fence])
        self.assertNotIn('ConnectionBudget(', text[connect:fence])  # No renewed verification allowance.


if __name__ == '__main__':
    unittest.main()
