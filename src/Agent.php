<?php

namespace Jenssegers\Agent;

use Detection\MobileDetect;
use Jaybizzle\CrawlerDetect\CrawlerDetect;

class Agent extends MobileDetect
{
    /**
     * A type for the version() method indicating a string return value.
     */
    private const string VERSION_TYPE_STRING = 'text';

    /**
     * A type for the version() method indicating a float return value.
     */
    private const string VERSION_TYPE_FLOAT = 'float';

    /**
     * List of desktop devices.
     */
    protected static array $desktopDevices = [
        'Macintosh' => 'Macintosh',
    ];

    /**
     * List of additional operating systems.
     */
    protected static array $additionalOperatingSystems = [
        'Windows' => 'Windows',
        'Windows NT' => 'Windows NT',
        'OS X' => 'Mac OS X',
        'Debian' => 'Debian',
        'Ubuntu' => 'Ubuntu',
        'Macintosh' => 'PPC',
        'OpenBSD' => 'OpenBSD',
        'Linux' => 'Linux',
        'ChromeOS' => 'CrOS',
    ];

    /**
     * List of additional browsers.
     */
    protected static array $additionalBrowsers = [
        'Opera Mini' => 'Opera Mini',
        'Opera' => 'Opera|OPR',
        'Edge' => 'Edge|Edg',
        'Coc Coc' => 'coc_coc_browser',
        'UCBrowser' => 'UCBrowser',
        'Vivaldi' => 'Vivaldi',
        'Chrome' => 'Chrome',
        'Firefox' => 'Firefox',
        'Safari' => 'Safari',
        'IE' => 'MSIE|IEMobile|MSIEMobile|Trident/[.0-9]+',
        'Netscape' => 'Netscape',
        'Mozilla' => 'Mozilla',
        'WeChat'  => 'MicroMessenger',
    ];

    /**
     * List of additional properties.
     */
    protected static array $additionalProperties = [
        // Operating systems
        'Windows' => 'Windows NT [VER]',
        'Windows NT' => 'Windows NT [VER]',
        'OS X' => 'OS X [VER]',
        'BlackBerryOS' => ['BlackBerry[\w]+/[VER]', 'BlackBerry.*Version/[VER]', 'Version/[VER]'],
        'AndroidOS' => 'Android [VER]',
        'ChromeOS' => 'CrOS x86_64 [VER]',

        // Browsers
        'Opera Mini' => 'Opera Mini/[VER]',
        'Opera' => [' OPR/[VER]', 'Opera Mini/[VER]', 'Version/[VER]', 'Opera [VER]'],
        'Netscape' => 'Netscape/[VER]',
        'Mozilla' => 'rv:[VER]',
        'IE' => ['IEMobile/[VER];', 'IEMobile [VER]', 'MSIE [VER];', 'rv:[VER]'],
        'Edge' => ['Edge/[VER]', 'Edg/[VER]'],
        'Vivaldi' => 'Vivaldi/[VER]',
        'Coc Coc' => 'coc_coc_browser/[VER]',
    ];

    protected static ?CrawlerDetect $crawlerDetect = null;

    /**
     * Get all detection rules. These rules include the additional
     * platforms and browsers and utilities.
     */
    public function getExtendedRules(): array
    {
        static $rules;

        if (!$rules) {
            $rules = static::mergeRules(
                static::$desktopDevices, // NEW
                static::$phoneDevices,
                static::$tabletDevices,
                static::$operatingSystems,
                static::$additionalOperatingSystems, // NEW
                static::$browsers,
                static::$additionalBrowsers, // NEW
            );
        }

        return $rules;
    }

    public function getCrawlerDetect(): CrawlerDetect
    {
        return static::$crawlerDetect ??= new CrawlerDetect();
    }

    public static function getBrowsers(): array
    {
        return static::mergeRules(
            static::$additionalBrowsers,
            static::$browsers,
        );
    }

    public static function getOperatingSystems(): array
    {
        return static::mergeRules(
            static::$operatingSystems,
            static::$additionalOperatingSystems,
        );
    }

    public static function getPlatforms(): array
    {
        return static::mergeRules(
            static::$operatingSystems,
            static::$additionalOperatingSystems,
        );
    }

    public static function getDesktopDevices(): array
    {
        return static::$desktopDevices;
    }

    public static function getProperties(): array
    {
        return static::mergeRules(
            static::$additionalProperties,
            static::$properties,
        );
    }

    /**
     * Get accept languages.
     */
    public function languages(?string $acceptLanguage = null): array
    {
        if ($acceptLanguage === null) {
            $acceptLanguage = $this->getHttpHeader('HTTP_ACCEPT_LANGUAGE');
        }

        if (!$acceptLanguage) {
            return [];
        }

        $languages = [];

        // Parse accept language string.
        foreach (explode(',', $acceptLanguage) as $piece) {
            $parts = explode(';', $piece);
            $language = strtolower($parts[0]);
            $priority = empty($parts[1]) ? 1. : floatval(str_replace('q=', '', $parts[1]));

            $languages[$language] = $priority;
        }

        // Sort languages by priority.
        arsort($languages);

        return array_keys($languages);
    }

    /**
     * Match a detection rule and return the matched key.
     */
    protected function findDetectionRulesAgainstUA(array $rules, ?string $userAgent = null): string|bool
    {
        $userAgent ??= $this->getUserAgent();

        foreach ($rules as $key => $_regex) {
            if (empty($_regex)) {
                continue;
            }

            if (is_array($_regex)) {
                foreach ($_regex as $regexString) {
                    if ($this->match($regexString, $userAgent)) {
                        return $key;
                    }
                }
            } else {
                if ($this->match($_regex, $userAgent)) {
                    return $key ?: reset($this->matchesArray);
                }
            }
        }

        return false;
    }

    /**
     * Get the browser name.
     */
    public function browser(?string $userAgent = null): string|bool
    {
        return $this->findDetectionRulesAgainstUA(static::getBrowsers(), $userAgent);
    }

    /**
     * Get the platform name.
     */
    public function platform(?string $userAgent = null): string|bool
    {
        return $this->findDetectionRulesAgainstUA(static::getPlatforms(), $userAgent);
    }

    /**
     * Get the device name.
     */
    public function device(?string $userAgent = null): string|bool
    {
        $rules = static::mergeRules(
            static::getDesktopDevices(),
            static::getPhoneDevices(),
            static::getTabletDevices(),
        );

        return $this->findDetectionRulesAgainstUA($rules, $userAgent);
    }

    /**
     * Get the robot name.
     */
    public function robot(?string $userAgent = null): string|bool
    {
        if ($this->getCrawlerDetect()->isCrawler($userAgent ?: $this->userAgent)) {
            return ucfirst($this->getCrawlerDetect()->getMatches());
        }

        return false;
    }

    /**
     * Check if the device is a desktop computer.
     */
    public function isDesktop(): bool
    {
        // Check specifically for cloudfront headers if the useragent === 'Amazon CloudFront'
        if ($this->getUserAgent() === 'Amazon CloudFront') {
            $cfHeaders = $this->getCfHeaders();
            if(array_key_exists('HTTP_CLOUDFRONT_IS_DESKTOP_VIEWER', $cfHeaders)) {
                return $cfHeaders['HTTP_CLOUDFRONT_IS_DESKTOP_VIEWER'] === 'true';
            }
        }

        return !$this->isMobile() && !$this->isTablet() && !$this->isRobot();
    }

    /**
     * Check if the device is a mobile phone.
     */
    public function isPhone(): bool
    {
        return $this->isMobile() && !$this->isTablet();
    }

    /**
     * Check if device is a robot.
     */
    public function isRobot(?string $userAgent = null): bool
    {
        return $this->getCrawlerDetect()->isCrawler($userAgent ?: $this->userAgent);
    }

    /**
     * Get the device type
     */
    public function deviceType(): string
    {
        return match (true) {
            $this->isDesktop() => 'desktop',
            $this->isPhone() => 'phone',
            $this->isTablet() => 'tablet',
            $this->isRobot() => 'robot',
            default => 'other',
        };
    }

    public function version(string $propertyName, string $type = self::VERSION_TYPE_STRING): float|string|bool
    {
        if ($propertyName === '') {
            return false;
        }

        // set the $type to the default if we don't recognize the type
        if ($type !== self::VERSION_TYPE_STRING && $type !== self::VERSION_TYPE_FLOAT) {
            $type = self::VERSION_TYPE_STRING;
        }

        $properties = self::getProperties();

        // Check if the property exists in the properties array.
        if (isset($properties[$propertyName])) {

            // Prepare the pattern to be matched.
            // Make sure we always deal with an array (string is converted).
            $properties[$propertyName] = (array) $properties[$propertyName];

            foreach ($properties[$propertyName] as $propertyMatchString) {
                if (is_array($propertyMatchString)) {
                    $propertyMatchString = implode('|', $propertyMatchString);
                }

                $propertyPattern = str_replace('[VER]', self::VERSION_REGEX, $propertyMatchString);

                // Identify and extract the version.
                preg_match(sprintf('#%s#is', $propertyPattern), $this->userAgent, $match);

                if (!empty($match[1])) {
                    $version = ($type === self::VERSION_TYPE_FLOAT ? $this->prepareVersionNo($match[1]) : $match[1]);

                    return $version;
                }
            }
        }

        return false;
    }

    /**
     * Merge multiple rules into one array.
     */
    protected static function mergeRules(...$all): array
    {
        $merged = [];

        foreach ($all as $rules) {
            foreach ($rules as $key => $value) {
                if (empty($merged[$key])) {
                    $merged[$key] = $value;
                } elseif (is_array($merged[$key])) {
                    $merged[$key][] = $value;
                } else {
                    $merged[$key] .= '|' . $value;
                }
            }
        }

        return $merged;
    }

    protected function matchUserAgentWithRule(string $ruleName): bool
    {
        $result = false;
        // Make the keys lowercase, so we can match: isIphone(), isiPhone(), isiphone(), etc.
        $ruleName = strtolower($ruleName);
        // change the keys to lower case
        $_rules = array_change_key_case($this->getExtendedRules());

        if (false === empty($_rules[$ruleName])) {
            $regexString = $_rules[$ruleName];
            if (is_array($_rules[$ruleName])) {
                $regexString = implode("|", $_rules[$ruleName]);
            }
            $result = $this->match($regexString, $this->getUserAgent());
        }

        return $result;
    }
}