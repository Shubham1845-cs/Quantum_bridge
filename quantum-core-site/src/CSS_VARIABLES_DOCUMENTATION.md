# CSS Variables Documentation - index.css Backup

**Backup Created:** Task 8.1 - Lovable Landing Page Integration  
**Original File:** `src/index.css`  
**Backup File:** `src/index.css.backup`

## Dashboard Custom Variables (@theme scope)

### Colors
- `--color-cyber-cyan`: #00FFFF
- `--color-neon-purple`: #8A2BE2
- `--color-deep-space`: #05050a
- `--color-void`: #080810

### Shadows
- `--shadow-neon-cyan`: 0 0 10px #00FFFF, 0 0 20px #00FFFF
- `--shadow-neon-purple`: 0 0 10px #8A2BE2, 0 0 20px #8A2BE2
- `--shadow-neon-subtle`: 0 0 5px rgba(0, 255, 255, 0.25), 0 0 15px rgba(0, 255, 255, 0.12)

### Fonts (@theme scope)
- `--font-space`: 'Space Grotesk', sans-serif

## Landing Page Variables (@theme scope)

### Radius System
- `--radius-sm`: calc(var(--radius) - 4px)
- `--radius-md`: calc(var(--radius) - 2px)
- `--radius-lg`: var(--radius)
- `--radius-xl`: calc(var(--radius) + 4px)
- `--radius-2xl`: calc(var(--radius) + 8px)
- `--radius-3xl`: calc(var(--radius) + 12px)
- `--radius-4xl`: calc(var(--radius) + 16px)

### Color System (References to :root variables)
- `--color-background`: var(--background)
- `--color-foreground`: var(--foreground)
- `--color-card`: var(--card)
- `--color-card-foreground`: var(--card-foreground)
- `--color-popover`: var(--popover)
- `--color-popover-foreground`: var(--popover-foreground)
- `--color-primary`: var(--primary)
- `--color-primary-foreground`: var(--primary-foreground)
- `--color-secondary`: var(--secondary)
- `--color-secondary-foreground`: var(--secondary-foreground)
- `--color-muted`: var(--muted)
- `--color-muted-foreground`: var(--muted-foreground)
- `--color-accent`: var(--accent)
- `--color-accent-foreground`: var(--accent-foreground)
- `--color-destructive`: var(--destructive)
- `--color-destructive-foreground`: var(--destructive-foreground)
- `--color-border`: var(--border)
- `--color-input`: var(--input)
- `--color-ring`: var(--ring)
- `--color-ring-offset-background`: var(--background)
- `--color-chart-1`: var(--chart-1)
- `--color-chart-2`: var(--chart-2)
- `--color-chart-3`: var(--chart-3)
- `--color-chart-4`: var(--chart-4)
- `--color-chart-5`: var(--chart-5)
- `--color-sidebar`: var(--sidebar)
- `--color-sidebar-foreground`: var(--sidebar-foreground)
- `--color-sidebar-primary`: var(--sidebar-primary)
- `--color-sidebar-primary-foreground`: var(--sidebar-primary-foreground)
- `--color-sidebar-accent`: var(--sidebar-accent)
- `--color-sidebar-accent-foreground`: var(--sidebar-accent-foreground)
- `--color-sidebar-border`: var(--sidebar-border)
- `--color-sidebar-ring`: var(--sidebar-ring)

## Root Variables (:root scope)

### Fonts
- `--font-space`: 'Space Grotesk', sans-serif
- `--font-heading`: 'Helvetica Now Display Bold', sans-serif
- `--font-body`: 'Inter', sans-serif

### Radius Base
- `--radius`: 0.625rem

### Light Mode Colors (oklch format)
- `--background`: oklch(1 0 0)
- `--foreground`: oklch(0.129 0.042 264.695)
- `--card`: oklch(1 0 0)
- `--card-foreground`: oklch(0.129 0.042 264.695)
- `--popover`: oklch(1 0 0)
- `--popover-foreground`: oklch(0.129 0.042 264.695)
- `--primary`: oklch(0.208 0.042 265.755)
- `--primary-foreground`: oklch(0.984 0.003 247.858)
- `--secondary`: oklch(0.968 0.007 247.896)
- `--secondary-foreground`: oklch(0.208 0.042 265.755)
- `--muted`: oklch(0.968 0.007 247.896)
- `--muted-foreground`: oklch(0.554 0.046 257.417)
- `--accent`: oklch(0.968 0.007 247.896)
- `--accent-foreground`: oklch(0.208 0.042 265.755)
- `--destructive`: oklch(0.577 0.245 27.325)
- `--destructive-foreground`: oklch(0.984 0.003 247.858)
- `--border`: oklch(0.929 0.013 255.508)
- `--input`: oklch(0.929 0.013 255.508)
- `--ring`: oklch(0.704 0.04 256.788)
- `--chart-1`: oklch(0.646 0.222 41.116)
- `--chart-2`: oklch(0.6 0.118 184.704)
- `--chart-3`: oklch(0.398 0.07 227.392)
- `--chart-4`: oklch(0.828 0.189 84.429)
- `--chart-5`: oklch(0.769 0.188 70.08)
- `--sidebar`: oklch(0.984 0.003 247.858)
- `--sidebar-foreground`: oklch(0.129 0.042 264.695)
- `--sidebar-primary`: oklch(0.208 0.042 265.755)
- `--sidebar-primary-foreground`: oklch(0.984 0.003 247.858)
- `--sidebar-accent`: oklch(0.968 0.007 247.896)
- `--sidebar-accent-foreground`: oklch(0.208 0.042 265.755)
- `--sidebar-border`: oklch(0.929 0.013 255.508)
- `--sidebar-ring`: oklch(0.704 0.04 256.788)

## Dark Mode Variables (.dark scope)

### Dark Mode Colors (oklch format)
- `--background`: oklch(0.129 0.042 264.695)
- `--foreground`: oklch(0.984 0.003 247.858)
- `--card`: oklch(0.208 0.042 265.755)
- `--card-foreground`: oklch(0.984 0.003 247.858)
- `--popover`: oklch(0.208 0.042 265.755)
- `--popover-foreground`: oklch(0.984 0.003 247.858)
- `--primary`: oklch(0.929 0.013 255.508)
- `--primary-foreground`: oklch(0.208 0.042 265.755)
- `--secondary`: oklch(0.279 0.041 260.031)
- `--secondary-foreground`: oklch(0.984 0.003 247.858)
- `--muted`: oklch(0.279 0.041 260.031)
- `--muted-foreground`: oklch(0.704 0.04 256.788)
- `--accent`: oklch(0.279 0.041 260.031)
- `--accent-foreground`: oklch(0.984 0.003 247.858)
- `--destructive`: oklch(0.704 0.191 22.216)
- `--destructive-foreground`: oklch(0.984 0.003 247.858)
- `--border`: oklch(1 0 0 / 10%)
- `--input`: oklch(1 0 0 / 15%)
- `--ring`: oklch(0.551 0.027 264.364)
- `--chart-1`: oklch(0.488 0.243 264.376)
- `--chart-2`: oklch(0.696 0.17 162.48)
- `--chart-3`: oklch(0.769 0.188 70.08)
- `--chart-4`: oklch(0.627 0.265 303.9)
- `--chart-5`: oklch(0.645 0.246 16.439)
- `--sidebar`: oklch(0.208 0.042 265.755)
- `--sidebar-foreground`: oklch(0.984 0.003 247.858)
- `--sidebar-primary`: oklch(0.488 0.243 264.376)
- `--sidebar-primary-foreground`: oklch(0.984 0.003 247.858)
- `--sidebar-accent`: oklch(0.279 0.041 260.031)
- `--sidebar-accent-foreground`: oklch(0.984 0.003 247.858)
- `--sidebar-border`: oklch(1 0 0 / 10%)
- `--sidebar-ring`: oklch(0.551 0.027 264.364)

## Additional Styles

### Body Styles
- Font Family: var(--font-space), sans-serif
- Background: #05050a
- Color: white
- Overflow-x: hidden

### Custom Classes
- `.font-space`: Uses Space Grotesk font
- `.text-gradient-cyan`: Cyan to purple gradient text

### Animations
- `@keyframes pulse-glow`: Opacity pulse (0.6 to 1)
- `@keyframes float`: Vertical floating motion (-10px)
- `@keyframes scanline`: Vertical scan effect

### Custom Scrollbar
- Scrollbar hidden for all elements
- Custom selection color: Cyan (#00FFFF) background with black text

## Notes

This backup was created before merging Lovable landing page styles with the dashboard styles. The original file contains:
1. Dashboard-specific variables (cyber-cyan, neon-purple themes)
2. Landing page color system (oklch format with light/dark modes)
3. Tailwind CSS v4 @theme directive
4. Custom animations and utility classes
