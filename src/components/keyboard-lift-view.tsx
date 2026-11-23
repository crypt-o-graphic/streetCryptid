import { type ReactNode, useCallback, useEffect, useRef } from 'react';
import {
  findNodeHandle,
  type StyleProp,
  View,
  type ViewInstance,
  type ViewStyle,
} from 'react-native';
import {
  KeyboardControllerNative,
  KeyboardEvents,
  useReanimatedKeyboardAnimation,
  useWindowDimensions,
} from 'react-native-keyboard-controller';
import Animated, { useAnimatedStyle, useSharedValue } from 'react-native-reanimated';

/**
 * Lifts its content clear of the software keyboard, frame by frame with the keyboard's own
 * animation, and only by as much as the keyboard would cover it.
 *
 * This is a transform on the UI thread, driven by react-native-keyboard-controller's native
 * keyboard tracking. React Native's `KeyboardAvoidingView` instead re-lays out the whole screen
 * once from JS (padding plus `LayoutAnimation`), which made the field above a pairing panel
 * stutter as it shrank. It also compared a window-space keyboard with a parent-relative frame, so
 * inside the Settings sheet the panel stopped short by the sheet's top offset. Here the view's
 * bottom is measured in window coordinates, so a full-screen route, an iOS sheet and a panel
 * centred beside the field all move by their real overlap.
 *
 * `coverableBottom` is how much of the view's own bottom may go under the keyboard. A panel's
 * home-indicator margin is not needed while the keyboard covers the indicator.
 */
export function KeyboardLiftView({
  children,
  coverableBottom = 0,
  style,
}: {
  children: ReactNode;
  coverableBottom?: number;
  style?: StyleProp<ViewStyle>;
}) {
  // The anchor never moves, so measuring it is never thrown off by the lift itself.
  const anchor = useRef<ViewInstance>(null);
  const bottom = useSharedValue<number | null>(null);
  const { height: keyboard } = useReanimatedKeyboardAnimation();
  // The library's own reading, in the same space as the keyboard height it reports.
  const { height: windowHeight } = useWindowDimensions();

  const measure = useCallback(() => {
    const view = anchor.current;
    if (!view) return;
    const tag = findNodeHandle(view);
    const fallback = () =>
      view.measureInWindow((_x, y, _w, h) => {
        if (Number.isFinite(y + h)) bottom.value = y + h;
      });
    const native = tag == null ? undefined : KeyboardControllerNative?.viewPositionInWindow;
    if (!native || tag == null) {
      fallback();
      return;
    }
    // Web answers every view with an all-zero rect.
    native(tag).then(({ y, width, height }) => {
      if (width > 0 && height > 0 && Number.isFinite(y + height)) bottom.value = y + height;
      else fallback();
    }, fallback);
  }, [bottom]);

  // A layout pass does not fire when only an ancestor moves (a sheet still sliding in), so the
  // position is read again as the keyboard starts to rise. The answer lands within a frame, early
  // in the keyboard's animation.
  useEffect(() => {
    const subscription = KeyboardEvents.addListener('keyboardWillShow', measure);
    return () => subscription.remove();
  }, [measure]);

  const lift = useAnimatedStyle(() => {
    // `keyboard` is negative while the keyboard is up. Until the view has been measured, behave
    // as though it sits on the window's bottom edge.
    const below = bottom.value == null ? 0 : Math.max(0, windowHeight - bottom.value);
    return { transform: [{ translateY: Math.min(0, keyboard.value + below + coverableBottom) }] };
  }, [windowHeight, coverableBottom]);

  return (
    <View collapsable={false} onLayout={measure} ref={anchor} style={style}>
      <Animated.View style={lift}>{children}</Animated.View>
    </View>
  );
}
