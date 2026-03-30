import { useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import dashboardService from '../services/dashboardService';
import packetService from '../services/packetService';
import analyticsService from '../services/analyticsService';

/**
 * Custom hook to automatically cancel all pending API requests
 * when the user navigates to a different route or when the component unmounts.
 * 
 * This prevents:
 * - Requests from continuing after user leaves the page
 * - Response updates from affecting the wrong component
 * - Memory leaks from dangling requests
 * - State updates on unmounted components
 * 
 * Usage:
 *   const MyComponent: React.FC = () => {
 *     useRouteCleanup();  // That's it!
 *     // Component logic here
 *   };
 */
export const useRouteCleanup = () => {
  const location = useLocation();
  const isCleaningUp = useRef(false);

  useEffect(() => {
    // Mark that we're not in cleanup yet
    isCleaningUp.current = false;

    // Return cleanup function that runs on:
    // 1. Component unmount
    // 2. Route change (location changes)
    return () => {
      if (isCleaningUp.current) return; // Prevent double cleanup
      isCleaningUp.current = true;

      console.debug(`[useRouteCleanup] Cleaning up requests for route: ${location.pathname}`);

      // Cancel all pending requests across all services
      try {
        dashboardService.cancelRequests?.();
      } catch (e) {
        console.debug('[useRouteCleanup] Dashboard cleanup error:', e);
      }

      try {
        packetService.cancelRequests?.();
      } catch (e) {
        console.debug('[useRouteCleanup] Packet cleanup error:', e);
      }

      try {
        analyticsService.cancelRequests?.();
      } catch (e) {
        console.debug('[useRouteCleanup] Analytics cleanup error:', e);
      }
    };
  }, [location]); // Re-run when route changes
};

/**
 * Alternative: Manual cleanup for services
 * Use this if you need more granular control
 */
export const cancelAllServiceRequests = (): void => {
  try {
    dashboardService.cancelRequests?.();
  } catch (e) {
    console.debug('[cancelAllServiceRequests] Dashboard error:', e);
  }

  try {
    packetService.cancelRequests?.();
  } catch (e) {
    console.debug('[cancelAllServiceRequests] Packet error:', e);
  }

  try {
    analyticsService.cancelRequests?.();
  } catch (e) {
    console.debug('[cancelAllServiceRequests] Analytics error:', e);
  }
};
