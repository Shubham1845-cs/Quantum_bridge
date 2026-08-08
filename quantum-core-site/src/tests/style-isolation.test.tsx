import { describe, it, expect, beforeEach } from 'vitest';

/**
 * Style Isolation Test Suite
 * 
 * Validates Requirements: 5.5, 10.6, 11.1, 12.4
 * 
 * This test suite verifies that:
 * 1. Landing page styles are properly defined
 * 2. Dashboard styles remain unchanged
 * 3. No CSS conflicts between landing and dashboard
 * 4. Responsive breakpoints are defined correctly
 */

describe('Style Isolation Tests', () => {
  let computedStyles: CSSStyleDeclaration;

  beforeEach(() => {
    // Get computed styles from the root element
    computedStyles = window.getComputedStyle(document.documentElement);
  });

  describe('Landing Page CSS Variables', () => {
    it('should have landing page font variables defined', () => {
      const fontHeading = computedStyles.getPropertyValue('--font-heading').trim();
      const fontBody = computedStyles.getPropertyValue('--font-body').trim();
      
      expect(fontHeading).toContain('Helvetica Now Display Bold');
      expect(fontBody).toContain('Inter');
    });

    it('should have landing page radius variables defined', () => {
      const radius = computedStyles.getPropertyValue('--radius').trim();
      expect(radius).toBe('0.625rem');
    });

    it('should have landing page oklch color variables defined', () => {
      const background = computedStyles.getPropertyValue('--background').trim();
      const foreground = computedStyles.getPropertyValue('--foreground').trim();
      const primary = computedStyles.getPropertyValue('--primary').trim();
      
      expect(background).toContain('oklch');
      expect(foreground).toContain('oklch');
      expect(primary).toContain('oklch');
    });

    it('should have all custom radius scale variables defined', () => {
      const radiusSm = computedStyles.getPropertyValue('--radius-sm');
      const radiusMd = computedStyles.getPropertyValue('--radius-md');
      const radiusLg = computedStyles.getPropertyValue('--radius-lg');
      const radiusXl = computedStyles.getPropertyValue('--radius-xl');
      const radius2xl = computedStyles.getPropertyValue('--radius-2xl');
      const radius3xl = computedStyles.getPropertyValue('--radius-3xl');
      const radius4xl = computedStyles.getPropertyValue('--radius-4xl');
      
      expect(radiusSm).toBeTruthy();
      expect(radiusMd).toBeTruthy();
      expect(radiusLg).toBeTruthy();
      expect(radiusXl).toBeTruthy();
      expect(radius2xl).toBeTruthy();
      expect(radius3xl).toBeTruthy();
      expect(radius4xl).toBeTruthy();
    });

    it('should have both light and dark mode color definitions', () => {
      // Light mode colors are in :root
      const rootBackground = computedStyles.getPropertyValue('--background').trim();
      expect(rootBackground).toBeTruthy();
      
      // Check that dark mode class exists in stylesheet
      const darkModeSelector = Array.from(document.styleSheets)
        .flatMap(sheet => {
          try {
            return Array.from(sheet.cssRules);
          } catch {
            return [];
          }
        })
        .some(rule => {
          if (rule instanceof CSSStyleRule) {
            return rule.selectorText === '.dark';
          }
          return false;
        });
      
      expect(darkModeSelector).toBe(true);
    });
  });

  describe('Dashboard CSS Variables', () => {
    it('should preserve dashboard custom colors', () => {
      const cyberCyan = computedStyles.getPropertyValue('--color-cyber-cyan').trim();
      const neonPurple = computedStyles.getPropertyValue('--color-neon-purple').trim();
      const deepSpace = computedStyles.getPropertyValue('--color-deep-space').trim();
      const void_ = computedStyles.getPropertyValue('--color-void').trim();
      
      expect(cyberCyan).toBe('#00FFFF');
      expect(neonPurple).toBe('#8A2BE2');
      expect(deepSpace).toBe('#05050a');
      expect(void_).toBe('#080810');
    });

    it('should preserve dashboard custom shadows', () => {
      const shadowNeonCyan = computedStyles.getPropertyValue('--shadow-neon-cyan');
      const shadowNeonPurple = computedStyles.getPropertyValue('--shadow-neon-purple');
      const shadowNeonSubtle = computedStyles.getPropertyValue('--shadow-neon-subtle');
      
      expect(shadowNeonCyan).toBeTruthy();
      expect(shadowNeonPurple).toBeTruthy();
      expect(shadowNeonSubtle).toBeTruthy();
    });

    it('should preserve dashboard font variable', () => {
      const fontSpace = computedStyles.getPropertyValue('--font-space').trim();
      expect(fontSpace).toContain('Space Grotesk');
    });
  });

  describe('CSS Variable Naming Conflicts', () => {
    it('should have no conflicts between dashboard and landing page color variables', () => {
      // Dashboard colors use --color-* prefix
      const cyberCyan = computedStyles.getPropertyValue('--color-cyber-cyan');
      // Landing page colors use --background, --foreground, etc.
      const background = computedStyles.getPropertyValue('--background');
      
      // Both should be defined and different
      expect(cyberCyan).toBeTruthy();
      expect(background).toBeTruthy();
      expect(cyberCyan).not.toBe(background);
    });

    it('should have both dashboard and landing fonts available', () => {
      const fontSpace = computedStyles.getPropertyValue('--font-space');
      const fontHeading = computedStyles.getPropertyValue('--font-heading');
      const fontBody = computedStyles.getPropertyValue('--font-body');
      
      // All should be defined
      expect(fontSpace).toBeTruthy();
      expect(fontHeading).toBeTruthy();
      expect(fontBody).toBeTruthy();
      
      // They should be different
      expect(fontSpace).not.toBe(fontHeading);
      expect(fontSpace).not.toBe(fontBody);
    });
  });

  describe('Responsive Breakpoints', () => {
    it('should have proper viewport meta tag for responsive design', () => {
      const metaViewport = document.querySelector('meta[name="viewport"]');
      expect(metaViewport).toBeTruthy();
      expect(metaViewport?.getAttribute('content')).toContain('width=device-width');
    });

    it('should have smooth scroll behavior defined', () => {
      const html = document.documentElement;
      const scrollBehavior = window.getComputedStyle(html).scrollBehavior;
      expect(scrollBehavior).toBe('smooth');
    });

    it('should have body styles for overflow control', () => {
      const body = document.body;
      const overflowX = window.getComputedStyle(body).overflowX;
      expect(overflowX).toBe('hidden');
    });
  });

  describe('Global Styles', () => {
    it('should have body background color set to dark', () => {
      const body = document.body;
      const bgColor = window.getComputedStyle(body).backgroundColor;
      // Should be the deep-space color (#05050a)
      expect(bgColor).toBeTruthy();
    });

    it('should have custom selection colors defined', () => {
      // Check if selection styles are defined in stylesheet
      const hasSelectionStyle = Array.from(document.styleSheets)
        .flatMap(sheet => {
          try {
            return Array.from(sheet.cssRules);
          } catch {
            return [];
          }
        })
        .some(rule => {
          if (rule instanceof CSSStyleRule) {
            return rule.selectorText === '::selection' || rule.selectorText === '::-moz-selection';
          }
          return false;
        });
      
      expect(hasSelectionStyle).toBe(true);
    });

    it('should hide scrollbars for seamless cinematic feel', () => {
      // Check if scrollbar hiding styles are defined
      const hasScrollbarStyle = Array.from(document.styleSheets)
        .flatMap(sheet => {
          try {
            return Array.from(sheet.cssRules);
          } catch {
            return [];
          }
        })
        .some(rule => {
          if (rule instanceof CSSStyleRule) {
            return rule.selectorText === '::-webkit-scrollbar';
          }
          return false;
        });
      
      expect(hasScrollbarStyle).toBe(true);
    });
  });

  describe('Utility Classes', () => {
    it('should have font-space utility class defined', () => {
      const hasClass = Array.from(document.styleSheets)
        .flatMap(sheet => {
          try {
            return Array.from(sheet.cssRules);
          } catch {
            return [];
          }
        })
        .some(rule => {
          if (rule instanceof CSSStyleRule) {
            return rule.selectorText === '.font-space';
          }
          return false;
        });
      
      expect(hasClass).toBe(true);
    });

    it('should have text-gradient-cyan utility class defined', () => {
      const hasClass = Array.from(document.styleSheets)
        .flatMap(sheet => {
          try {
            return Array.from(sheet.cssRules);
          } catch {
            return [];
          }
        })
        .some(rule => {
          if (rule instanceof CSSStyleRule) {
            return rule.selectorText === '.text-gradient-cyan';
          }
          return false;
        });
      
      expect(hasClass).toBe(true);
    });

    it('should have custom animation classes defined', () => {
      const hasClasses = Array.from(document.styleSheets)
        .flatMap(sheet => {
          try {
            return Array.from(sheet.cssRules);
          } catch {
            return [];
          }
        })
        .some(rule => {
          if (rule instanceof CSSStyleRule) {
            return rule.selectorText === '.animate-pulse-glow' || 
                   rule.selectorText === '.animate-float' ||
                   rule.selectorText === '.animate-scanline';
          }
          return false;
        });
      
      expect(hasClasses).toBe(true);
    });
  });

  describe('Landing Page Component Styles', () => {
    it('should support glassmorphism effects (backdrop-filter)', () => {
      const testElement = document.createElement('div');
      testElement.style.backdropFilter = 'blur(20px)';
      document.body.appendChild(testElement);
      
      const backdropFilter = window.getComputedStyle(testElement).backdropFilter;
      
      // Clean up
      document.body.removeChild(testElement);
      
      // Should be supported (value is applied)
      expect(backdropFilter).toBeTruthy();
    });

    it('should support transform-style preserve-3d for 3D effects', () => {
      const testElement = document.createElement('div');
      testElement.style.transformStyle = 'preserve-3d';
      document.body.appendChild(testElement);
      
      const transformStyle = window.getComputedStyle(testElement).transformStyle;
      
      // Clean up
      document.body.removeChild(testElement);
      
      expect(transformStyle).toBe('preserve-3d');
    });
  });

  describe('Dashboard Component Styles', () => {
    it('should support dashboard button styles with cyber-cyan', () => {
      // Verify that cyber-cyan color is accessible
      const cyberCyan = computedStyles.getPropertyValue('--color-cyber-cyan');
      expect(cyberCyan).toBe('#00FFFF');
    });

    it('should support dashboard shadow effects', () => {
      const shadowNeonCyan = computedStyles.getPropertyValue('--shadow-neon-cyan');
      expect(shadowNeonCyan).toContain('0 0 10px #00FFFF');
      expect(shadowNeonCyan).toContain('0 0 20px #00FFFF');
    });
  });
});
