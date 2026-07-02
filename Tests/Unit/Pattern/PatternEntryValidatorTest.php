<?php

declare(strict_types=1);

namespace Flowd\Typo3Firewall\Tests\Unit\Pattern;

use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Typo3Firewall\Pattern\PatternEntryValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(PatternEntryValidator::class)]
final class PatternEntryValidatorTest extends TestCase
{
    private PatternEntryValidator $patternEntryValidator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->patternEntryValidator = new PatternEntryValidator();
    }

    #[Test]
    public function validateAcceptsValidIpEntry(): void
    {
        $this->patternEntryValidator->validate(new PatternEntry(kind: PatternKind::IP, value: '192.168.1.1'));
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function validateThrowsForEmptyValue(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Pattern value must not be empty');
        $this->expectExceptionCode(1770244701);

        $this->patternEntryValidator->validate(new PatternEntry(kind: PatternKind::IP, value: ''));
    }

    /**
     * @return array<string, array{0: PatternKind}>
     */
    public static function headerKindProvider(): array
    {
        return [
            'header_exact' => [PatternKind::HEADER_EXACT],
            'header_regex' => [PatternKind::HEADER_REGEX],
        ];
    }

    #[Test]
    #[DataProvider('headerKindProvider')]
    public function validateThrowsWhenHeaderKindHasNullTarget(PatternKind $patternKind): void
    {
        $value = $patternKind === PatternKind::HEADER_REGEX ? '/curl/' : 'curl/7.68.0';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('requires the target field to contain the header name');
        $this->expectExceptionCode(1779136101);

        $this->patternEntryValidator->validate(new PatternEntry(kind: $patternKind, value: $value));
    }

    #[Test]
    #[DataProvider('headerKindProvider')]
    public function validateThrowsWhenHeaderKindTargetIsEmpty(PatternKind $patternKind): void
    {
        $value = $patternKind === PatternKind::HEADER_REGEX ? '/curl/' : 'curl/7.68.0';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('requires the target field to contain the header name');

        $this->patternEntryValidator->validate(new PatternEntry(kind: $patternKind, value: $value, target: ''));
    }

    #[Test]
    #[DataProvider('headerKindProvider')]
    public function validateThrowsWhenHeaderKindTargetIsWhitespace(PatternKind $patternKind): void
    {
        $value = $patternKind === PatternKind::HEADER_REGEX ? '/curl/' : 'curl/7.68.0';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('requires the target field to contain the header name');

        $this->patternEntryValidator->validate(new PatternEntry(kind: $patternKind, value: $value, target: '   '));
    }

    #[Test]
    #[DataProvider('headerKindProvider')]
    public function validateAcceptsHeaderKindWithTarget(PatternKind $patternKind): void
    {
        $value = $patternKind === PatternKind::HEADER_REGEX ? '/curl/' : 'curl/7.68.0';

        $this->patternEntryValidator->validate(new PatternEntry(kind: $patternKind, value: $value, target: 'user-agent'));
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function validateIgnoresTargetForNonHeaderKinds(): void
    {
        $this->patternEntryValidator->validate(new PatternEntry(kind: PatternKind::IP, value: '1.1.1.1'));
        $this->patternEntryValidator->validate(new PatternEntry(kind: PatternKind::PATH_EXACT, value: '/admin', target: ''));
        $this->expectNotToPerformAssertions();
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function validIpProvider(): array
    {
        return [
            'ipv4' => ['192.168.1.1'],
            'ipv4 zeros' => ['0.0.0.0'],
            'ipv6 compressed' => ['2001:db8::1'],
            'ipv6 loopback' => ['::1'],
        ];
    }

    #[Test]
    #[DataProvider('validIpProvider')]
    public function validateAcceptsValidIpAddresses(string $ip): void
    {
        $this->patternEntryValidator->validate(new PatternEntry(kind: PatternKind::IP, value: $ip));
        $this->expectNotToPerformAssertions();
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function invalidIpProvider(): array
    {
        return [
            'word' => ['localhost'],
            'partial' => ['192.168.1'],
            'out of range' => ['256.1.1.1'],
            'cidr' => ['192.168.1.0/24'],
        ];
    }

    #[Test]
    #[DataProvider('invalidIpProvider')]
    public function validateRejectsInvalidIpAddresses(string $ip): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('Invalid IP address: %s', $ip));
        $this->expectExceptionCode(1770244710);

        $this->patternEntryValidator->validate(new PatternEntry(kind: PatternKind::IP, value: $ip));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function validCidrProvider(): array
    {
        return [
            'ipv4 /0' => ['0.0.0.0/0'],
            'ipv4 /24' => ['192.168.1.0/24'],
            'ipv4 /32' => ['192.168.1.1/32'],
            'ipv6 /0' => ['::/0'],
            'ipv6 /64' => ['2001:db8::/64'],
            'ipv6 /128' => ['::1/128'],
        ];
    }

    #[Test]
    #[DataProvider('validCidrProvider')]
    public function validateAcceptsValidCidr(string $cidr): void
    {
        $this->patternEntryValidator->validate(new PatternEntry(kind: PatternKind::CIDR, value: $cidr));
        $this->expectNotToPerformAssertions();
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function invalidCidrProvider(): array
    {
        return [
            'no prefix' => ['192.168.1.0'],
            'prefix too high ipv4' => ['192.168.1.0/33'],
            'prefix too high ipv6' => ['2001:db8::/129'],
            'negative prefix' => ['192.168.1.0/-1'],
            'non-numeric prefix' => ['192.168.1.0/abc'],
            'invalid ip' => ['999.168.1.0/24'],
            'double slash' => ['192.168.1.0//24'],
        ];
    }

    #[Test]
    #[DataProvider('invalidCidrProvider')]
    public function validateRejectsInvalidCidr(string $cidr): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('Invalid CIDR notation: %s', $cidr));
        $this->expectExceptionCode(1770244715);

        $this->patternEntryValidator->validate(new PatternEntry(kind: PatternKind::CIDR, value: $cidr));
    }

    /**
     * @return array<string, array{0: PatternKind, 1: string}>
     */
    public static function regexKindProvider(): array
    {
        return [
            'path_regex' => [PatternKind::PATH_REGEX, '/admin/'],
            'header_regex' => [PatternKind::HEADER_REGEX, '/curl/i'],
            'request_regex' => [PatternKind::REQUEST_REGEX, '/\.php$/'],
        ];
    }

    #[Test]
    #[DataProvider('regexKindProvider')]
    public function validateAcceptsValidRegexForRegexKinds(PatternKind $patternKind, string $regex): void
    {
        $entry = $patternKind === PatternKind::HEADER_REGEX
            ? new PatternEntry(kind: $patternKind, value: $regex, target: 'user-agent')
            : new PatternEntry(kind: $patternKind, value: $regex);

        $this->patternEntryValidator->validate($entry);
        $this->expectNotToPerformAssertions();
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function invalidRegexProvider(): array
    {
        return [
            'unmatched bracket' => ['/[admin/'],
            'unmatched paren' => ['/(admin/'],
            'invalid modifier' => ['/admin/z'],
            'no delimiters' => ['admin'],
        ];
    }

    #[Test]
    #[DataProvider('invalidRegexProvider')]
    public function validateRejectsInvalidRegex(string $regex): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('Invalid regex pattern: %s', $regex));
        $this->expectExceptionCode(1770244720);

        $this->patternEntryValidator->validate(new PatternEntry(kind: PatternKind::PATH_REGEX, value: $regex));
    }

    #[Test]
    public function validateAcceptsPathExactAndPrefixWithoutRegexCheck(): void
    {
        // PATH_EXACT / PATH_PREFIX don't go through the regex check, so even regex-shaped values pass
        $this->patternEntryValidator->validate(new PatternEntry(kind: PatternKind::PATH_EXACT, value: '/[admin'));
        $this->patternEntryValidator->validate(new PatternEntry(kind: PatternKind::PATH_PREFIX, value: '/admin'));
        $this->expectNotToPerformAssertions();
    }
}
