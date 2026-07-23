import { useEffect } from 'react';

let lockCount = 0;
let previousHtmlOverflow = '';
let previousHtmlOverscrollBehavior = '';
let previousOverflow = '';
let previousOverscrollBehavior = '';
let previousPosition = '';
let previousTop = '';
let previousWidth = '';
let previousPaddingRight = '';
let previousScrollY = 0;

export function useBodyScrollLock(active: boolean): void {
  useEffect(() => {
    if (!active || typeof document === 'undefined' || typeof window === 'undefined') {
      return undefined;
    }

    lockCount += 1;
    if (lockCount === 1) {
      const scrollbarGap = Math.max(0, window.innerWidth - document.documentElement.clientWidth);
      previousScrollY = window.scrollY || document.documentElement.scrollTop || 0;
      previousHtmlOverflow = document.documentElement.style.overflow;
      previousHtmlOverscrollBehavior = document.documentElement.style.overscrollBehavior;
      previousOverflow = document.body.style.overflow;
      previousOverscrollBehavior = document.body.style.overscrollBehavior;
      previousPosition = document.body.style.position;
      previousTop = document.body.style.top;
      previousWidth = document.body.style.width;
      previousPaddingRight = document.body.style.paddingRight;
      document.documentElement.style.overflow = 'hidden';
      document.documentElement.style.overscrollBehavior = 'none';
      document.body.style.overflow = 'hidden';
      document.body.style.overscrollBehavior = 'none';
      document.body.style.position = 'fixed';
      document.body.style.top = `-${previousScrollY}px`;
      document.body.style.width = '100%';
      if (scrollbarGap > 0) {
        document.body.style.paddingRight = `${scrollbarGap}px`;
      }
    }

    return () => {
      lockCount = Math.max(0, lockCount - 1);
      if (lockCount === 0) {
        document.documentElement.style.overflow = previousHtmlOverflow;
        document.documentElement.style.overscrollBehavior = previousHtmlOverscrollBehavior;
        document.body.style.overflow = previousOverflow;
        document.body.style.overscrollBehavior = previousOverscrollBehavior;
        document.body.style.position = previousPosition;
        document.body.style.top = previousTop;
        document.body.style.width = previousWidth;
        document.body.style.paddingRight = previousPaddingRight;
        window.scrollTo(0, previousScrollY);
      }
    };
  }, [active]);
}
