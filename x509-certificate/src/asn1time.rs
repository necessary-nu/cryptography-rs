// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ASN.1 primitives related to time types.

use {
    bcder::{
        decode::{Constructed, DecodeError, Primitive, SliceSource, Source},
        encode::{PrimitiveContent, Values},
        Mode, Tag,
    },
    jiff::{Timestamp, civil::DateTime, tz::Offset},
    std::{
        fmt::{Display, Formatter},
        io::Write,
        ops::Deref,
        str::FromStr,
    },
};

/// Timezone formats of [GeneralizedTime] to allow.
///
/// X.690 allows [GeneralizedTime] to have multiple timezone formats. However,
/// various RFCs restrict which formats are allowed. This enumeration exists to
/// express which formats should be allowed by a parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneralizedTimeAllowedTimezone {
    /// Allow either `Z` or timezone offset formats.
    Any,

    /// `Z` timezone identifier only.
    Z,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Time {
    UtcTime(UtcTime),
    GeneralTime(GeneralizedTime),
}

impl Time {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_primitive(|tag, prim| match tag {
            Tag::UTC_TIME => Ok(Self::UtcTime(UtcTime::from_primitive(prim)?)),
            Tag::GENERALIZED_TIME => Ok(Self::GeneralTime(
                GeneralizedTime::from_primitive_no_fractional_or_timezone_offsets(prim)?,
            )),
            _ => Err(prim.content_err(format!("expected UTCTime or GeneralizedTime; got {}", tag))),
        })
    }

    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_primitive(|tag, prim| match tag {
            Tag::UTC_TIME => Ok(Self::UtcTime(UtcTime::from_primitive(prim)?)),
            Tag::GENERALIZED_TIME => Ok(Self::GeneralTime(
                GeneralizedTime::from_primitive_no_fractional_or_timezone_offsets(prim)?,
            )),
            _ => Err(prim.content_err(format!("expected UTCTime or GeneralizedTime; got {}", tag))),
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        match self {
            Self::UtcTime(utc) => (Some(utc.encode()), None),
            Self::GeneralTime(gt) => (None, Some(gt.encode())),
        }
    }
}

impl From<Timestamp> for Time {
    fn from(t: Timestamp) -> Self {
        if (1950..=2049).contains(&Offset::UTC.to_datetime(t).year()) {
            Self::UtcTime(UtcTime(t))
        } else {
            Self::GeneralTime(GeneralizedTime::from(t))
        }
    }
}

impl From<Time> for Timestamp {
    fn from(value: Time) -> Self {
        match value {
            Time::UtcTime(v) => v.into(),
            Time::GeneralTime(v) => v.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Zone {
    Utc,
    Offset(Offset),
}

impl Zone {
    fn offset(&self) -> Offset {
        match self {
            Self::Utc => Offset::UTC,
            Self::Offset(offset) => *offset,
        }
    }
}

impl Display for Zone {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Utc => f.write_str("Z"),
            Self::Offset(offset) => {
                let seconds = offset.seconds();
                let sign = if seconds < 0 { '-' } else { '+' };
                let absolute = seconds.unsigned_abs();
                write!(f, "{sign}{:02}{:02}", absolute / 3600, (absolute % 3600) / 60)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralizedTime {
    timestamp: Timestamp,
    fractional_seconds: bool,
    timezone: Zone,
}

impl GeneralizedTime {
    /// Take a value, not allowing fractional seconds and requiring the `Z` timezone identifier.
    pub fn take_from_no_fractional_z<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_primitive_if(Tag::GENERALIZED_TIME, |prim| {
            Self::from_primitive_no_fractional_or_timezone_offsets(prim)
        })
    }

    /// Take a value, allowing fractional seconds and requiring the `Z` timezone identifier.
    pub fn take_from_allow_fractional_z<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_primitive_if(Tag::GENERALIZED_TIME, |prim| {
            let data = prim.take_all()?;

            Self::parse(
                SliceSource::new(data.as_ref()),
                true,
                GeneralizedTimeAllowedTimezone::Z,
            )
            .map_err(|e| e.convert())
        })
    }

    /// Parse a [GeneralizedTime] from a primitive string and don't allow fractional seconds or timezone offsets.
    pub fn from_primitive_no_fractional_or_timezone_offsets<S: Source>(
        prim: &mut Primitive<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let data = prim.take_all()?;

        Self::parse(
            SliceSource::new(data.as_ref()),
            false,
            GeneralizedTimeAllowedTimezone::Z,
        )
        .map_err(|e| e.convert())
    }

    /// Parse GeneralizedTime string data.
    pub fn parse(
        source: SliceSource,
        allow_fractional_seconds: bool,
        tz: GeneralizedTimeAllowedTimezone,
    ) -> Result<Self, DecodeError<<SliceSource as Source>::Error>> {
        let data = source.slice();

        // This form is common and is most strict. So check for it quickly.
        if !allow_fractional_seconds
            && matches!(tz, GeneralizedTimeAllowedTimezone::Z)
            && data.len() != "YYYYMMDDHHMMSSZ".len()
        {
            return Err(source.content_err(format!(
                "{} is not of format YYYYMMDDHHMMSSZ",
                String::from_utf8_lossy(data)
            )));
        }

        if data.len() < 15 {
            return Err(source.content_err("GeneralizedTime value too short"));
        }

        let year = i32::from_str(
            std::str::from_utf8(&data[0..4]).map_err(|s| source.content_err(s.to_string()))?,
        )
        .map_err(|s| source.content_err(s.to_string()))?;
        let month = u32::from_str(
            std::str::from_utf8(&data[4..6]).map_err(|s| source.content_err(s.to_string()))?,
        )
        .map_err(|s| source.content_err(s.to_string()))?;
        let day = u32::from_str(
            std::str::from_utf8(&data[6..8]).map_err(|s| source.content_err(s.to_string()))?,
        )
        .map_err(|s| source.content_err(s.to_string()))?;
        let hour = u32::from_str(
            std::str::from_utf8(&data[8..10]).map_err(|s| source.content_err(s.to_string()))?,
        )
        .map_err(|s| source.content_err(s.to_string()))?;
        let minute = u32::from_str(
            std::str::from_utf8(&data[10..12]).map_err(|s| source.content_err(s.to_string()))?,
        )
        .map_err(|s| source.content_err(s.to_string()))?;
        let second = u32::from_str(
            std::str::from_utf8(&data[12..14]).map_err(|s| source.content_err(s.to_string()))?,
        )
        .map_err(|s| source.content_err(s.to_string()))?;

        let remaining = &data[14..];

        let (nano, remaining) = match allow_fractional_seconds {
            true => {
                if remaining.starts_with(b".") {
                    if let Some((nondigit_offset, _)) = remaining
                        .iter()
                        .enumerate()
                        .skip(1)
                        .find(|(_, c)| !c.is_ascii_digit())
                    {
                        let digits_count = nondigit_offset - 1;

                        if !(1..=9).contains(&digits_count) {
                            return Err(source.content_err(
                                "fractional seconds must contain between 1 and 9 digits",
                            ));
                        }

                        let (digits, remaining) = remaining.split_at(nondigit_offset);

                        let mut digits = std::str::from_utf8(&digits[1..])
                            .map_err(|s| source.content_err(s.to_string()))?
                            .to_string();
                        digits.extend(std::iter::repeat_n('0', 9 - digits_count));

                        (
                            u32::from_str(&digits)
                                .map_err(|s| source.content_err(s.to_string()))?,
                            remaining,
                        )
                    } else {
                        return Err(source.content_err(
                            "failed to locate timezone identifier after fractional seconds",
                        ));
                    }
                } else {
                    (0, remaining)
                }
            }
            false => (0, remaining),
        };

        let timezone = match tz {
            GeneralizedTimeAllowedTimezone::Z => {
                if remaining != b"Z" {
                    return Err(source.content_err(format!(
                        "timezone identifier {} not `Z`",
                        String::from_utf8_lossy(remaining)
                    )));
                }

                Zone::Utc
            }
            GeneralizedTimeAllowedTimezone::Any => {
                if remaining == b"Z" {
                    Zone::Utc
                } else {
                    if remaining.len() != 5 {
                        return Err(source.content_err(format!(
                            "`{}` is not a 5 character timezone identifier",
                            String::from_utf8_lossy(remaining)
                        )));
                    }

                    let east = match remaining[0] {
                        b'+' => true,
                        b'-' => false,
                        _ => {
                            return Err(source.content_err(format!(
                                "`{}` does not begin with a +- offset",
                                String::from_utf8_lossy(remaining)
                            )))
                        }
                    };

                    let offset_hours = u32::from_str(
                        std::str::from_utf8(&remaining[1..3])
                            .map_err(|s| source.content_err(s.to_string()))?,
                    )
                    .map_err(|s| source.content_err(s.to_string()))?;
                    let offset_minutes = u32::from_str(
                        std::str::from_utf8(&remaining[3..])
                            .map_err(|s| source.content_err(s.to_string()))?,
                    )
                    .map_err(|s| source.content_err(s.to_string()))?;

                    if offset_minutes > 59 {
                        return Err(source.content_err("timezone offset minutes exceed 59"));
                    }
                    if offset_hours > 23 {
                        return Err(source.content_err("timezone offset hours exceed 23"));
                    }

                    let offset_seconds = (offset_hours * 3600 + offset_minutes * 60) as i32;

                    Zone::Offset(
                        Offset::from_seconds(if east {
                            offset_seconds
                        } else {
                            -offset_seconds
                        })
                        .map_err(|error| source.content_err(error.to_string()))?,
                    )
                }
            }
        };

        let datetime = DateTime::new(
            i16::try_from(year).map_err(|error| source.content_err(error.to_string()))?,
            i8::try_from(month).map_err(|error| source.content_err(error.to_string()))?,
            i8::try_from(day).map_err(|error| source.content_err(error.to_string()))?,
            i8::try_from(hour).map_err(|error| source.content_err(error.to_string()))?,
            i8::try_from(minute).map_err(|error| source.content_err(error.to_string()))?,
            i8::try_from(second).map_err(|error| source.content_err(error.to_string()))?,
            i32::try_from(nano).map_err(|error| source.content_err(error.to_string()))?,
        )
        .map_err(|error| source.content_err(error.to_string()))?;
        let timestamp = timezone
            .offset()
            .to_timestamp(datetime)
            .map_err(|error| source.content_err(error.to_string()))?;

        Ok(Self {
            timestamp,
            fractional_seconds: nano > 0,
            timezone,
        })
    }
}

impl Display for GeneralizedTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let datetime = self.timezone.offset().to_datetime(self.timestamp);
        write!(
            f,
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            datetime.year(),
            datetime.month(),
            datetime.day(),
            datetime.hour(),
            datetime.minute(),
            datetime.second()
        )?;
        if self.fractional_seconds {
            let fractional = format!("{:09}", datetime.subsec_nanosecond());
            write!(f, ".{}", fractional.trim_end_matches('0'))?;
        }
        write!(f, "{}", self.timezone)
    }
}

impl From<GeneralizedTime> for Timestamp {
    fn from(gt: GeneralizedTime) -> Self {
        gt.timestamp
    }
}

impl From<Timestamp> for GeneralizedTime {
    fn from(timestamp: Timestamp) -> Self {
        Self {
            timestamp,
            fractional_seconds: Offset::UTC.to_datetime(timestamp).subsec_nanosecond() > 0,
            timezone: Zone::Utc,
        }
    }
}

impl PrimitiveContent for GeneralizedTime {
    const TAG: Tag = Tag::GENERALIZED_TIME;

    fn encoded_len(&self, _: Mode) -> usize {
        self.to_string().len()
    }

    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        target.write_all(self.to_string().as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtcTime(Timestamp);

impl From<Timestamp> for UtcTime {
    fn from(value: Timestamp) -> Self {
        Self(value)
    }
}

impl From<UtcTime> for Timestamp {
    fn from(value: UtcTime) -> Self {
        *value.deref()
    }
}

impl UtcTime {
    /// Obtain a new instance with now as the time.
    pub fn now() -> Self {
        Self(Timestamp::now())
    }

    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_primitive_if(Tag::UTC_TIME, |prim| Self::from_primitive(prim))
    }

    pub fn from_primitive<S: Source>(
        prim: &mut Primitive<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let data = prim.take_all()?;

        if data.len() != "YYMMDDHHMMSSZ".len() {
            return Err(prim.content_err("UTCTime not of expected length"));
        }

        let year = i32::from_str(
            std::str::from_utf8(&data[0..2]).map_err(|s| prim.content_err(s.to_string()))?,
        )
        .map_err(|s| prim.content_err(s.to_string()))?;

        let year = if year >= 50 { year + 1900 } else { year + 2000 };

        let month = u32::from_str(
            std::str::from_utf8(&data[2..4]).map_err(|s| prim.content_err(s.to_string()))?,
        )
        .map_err(|s| prim.content_err(s.to_string()))?;
        let day = u32::from_str(
            std::str::from_utf8(&data[4..6]).map_err(|s| prim.content_err(s.to_string()))?,
        )
        .map_err(|s| prim.content_err(s.to_string()))?;
        let hour = u32::from_str(
            std::str::from_utf8(&data[6..8]).map_err(|s| prim.content_err(s.to_string()))?,
        )
        .map_err(|s| prim.content_err(s.to_string()))?;
        let minute = u32::from_str(
            std::str::from_utf8(&data[8..10]).map_err(|s| prim.content_err(s.to_string()))?,
        )
        .map_err(|s| prim.content_err(s.to_string()))?;
        let second = u32::from_str(
            std::str::from_utf8(&data[10..12]).map_err(|s| prim.content_err(s.to_string()))?,
        )
        .map_err(|s| prim.content_err(s.to_string()))?;

        if data[12] != b'Z' {
            return Err(prim.content_err("UTCTime must end with `Z`"));
        }

        let datetime = DateTime::new(
            i16::try_from(year).map_err(|error| prim.content_err(error.to_string()))?,
            i8::try_from(month).map_err(|error| prim.content_err(error.to_string()))?,
            i8::try_from(day).map_err(|error| prim.content_err(error.to_string()))?,
            i8::try_from(hour).map_err(|error| prim.content_err(error.to_string()))?,
            i8::try_from(minute).map_err(|error| prim.content_err(error.to_string()))?,
            i8::try_from(second).map_err(|error| prim.content_err(error.to_string()))?,
            0,
        )
        .map_err(|error| prim.content_err(error.to_string()))?;
        let timestamp = Offset::UTC
            .to_timestamp(datetime)
            .map_err(|error| prim.content_err(error.to_string()))?;

        Ok(Self(timestamp))
    }
}

impl Display for UtcTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let datetime = Offset::UTC.to_datetime(self.0);
        let str = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            datetime.year() % 100,
            datetime.month(),
            datetime.day(),
            datetime.hour(),
            datetime.minute(),
            datetime.second()
        );
        write!(f, "{}", str)
    }
}

impl Deref for UtcTime {
    type Target = Timestamp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PrimitiveContent for UtcTime {
    const TAG: Tag = Tag::UTC_TIME;

    fn encoded_len(&self, _: Mode) -> usize {
        self.to_string().len()
    }

    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        target.write_all(self.to_string().as_bytes())
    }
}

#[cfg(test)]
mod test {
    use {super::*, bcder::decode::ContentError};

    #[test]
    fn generalized_time() -> Result<(), ContentError> {
        let gt = GeneralizedTime {
            timestamp: Timestamp::from_second(1_643_510_772).unwrap(),
            fractional_seconds: false,
            timezone: Zone::Utc,
        };
        assert_eq!(gt.to_string(), "20220130024612Z");

        let gt = GeneralizedTime {
            timestamp: Timestamp::from_second(1_643_507_172).unwrap(),
            fractional_seconds: false,
            timezone: Zone::Offset(Offset::from_seconds(3600).unwrap()),
        };
        assert_eq!(gt.to_string(), "20220130024612+0100");

        let gt = GeneralizedTime {
            timestamp: Timestamp::from_second(1_643_517_972).unwrap(),
            fractional_seconds: false,
            timezone: Zone::Offset(Offset::from_seconds(-7200).unwrap()),
        };
        assert_eq!(gt.to_string(), "20220130024612-0200");

        let gt = GeneralizedTime::parse(
            SliceSource::new(b"20220129133742Z"),
            true,
            GeneralizedTimeAllowedTimezone::Z,
        )?;
        let datetime = gt.timezone.offset().to_datetime(gt.timestamp);
        assert_eq!(datetime.year(), 2022);
        assert_eq!(datetime.month(), 1);
        assert_eq!(datetime.day(), 29);
        assert_eq!(datetime.hour(), 13);
        assert_eq!(datetime.minute(), 37);
        assert_eq!(datetime.second(), 42);
        assert_eq!(datetime.subsec_nanosecond(), 0);
        assert_eq!(format!("{}", gt.timezone), "Z");

        assert_eq!(gt.to_string(), "20220129133742Z");

        let gt = GeneralizedTime::parse(
            SliceSource::new(b"20220129133742.333Z"),
            true,
            GeneralizedTimeAllowedTimezone::Z,
        )?;
        assert_eq!(gt.to_string(), "20220129133742.333Z");

        let gt = GeneralizedTime::parse(
            SliceSource::new(b"20220129133742-0800"),
            false,
            GeneralizedTimeAllowedTimezone::Any,
        )?;
        assert_eq!(format!("{}", gt.timezone), "-0800");

        let gt = GeneralizedTime::parse(
            SliceSource::new(b"20220129133742+1000"),
            false,
            GeneralizedTimeAllowedTimezone::Any,
        )?;
        assert_eq!(format!("{}", gt.timezone), "+1000");

        let gt = GeneralizedTime::parse(
            SliceSource::new(b"20220129133742.333-0800"),
            true,
            GeneralizedTimeAllowedTimezone::Any,
        )?;
        assert_eq!(gt.to_string(), "20220129133742.333-0800");

        let gt = GeneralizedTime::parse(
            SliceSource::new(b"20220129133742+0100"),
            false,
            GeneralizedTimeAllowedTimezone::Any,
        )?;
        let utc: Timestamp = gt.into();
        assert_eq!(utc.to_string(), "2022-01-29T12:37:42Z");

        Ok(())
    }

    #[test]
    fn time_uses_generalized_time_outside_utc_time_range() {
        let in_range: Timestamp = "2049-12-31T00:00:00Z".parse().unwrap();
        assert!(matches!(Time::from(in_range), Time::UtcTime(_)));

        let out_of_range: Timestamp = "2050-01-01T00:00:00Z".parse().unwrap();
        assert!(matches!(Time::from(out_of_range), Time::GeneralTime(_)));
    }

    #[test]
    fn generalized_time_preserves_nanosecond_fraction() {
        let time = Timestamp::new(1_643_510_772, 1).unwrap();
        assert_eq!(GeneralizedTime::from(time).to_string(), "20220130024612.000000001Z");
    }

    #[test]
    fn generalized_time_invalid() {
        for allow_fractional_seconds in [false, true] {
            for allowed_timezone in [
                GeneralizedTimeAllowedTimezone::Any,
                GeneralizedTimeAllowedTimezone::Z,
            ] {
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b""),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"abcd"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"2022"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"202201"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"2022013012"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"202201301230"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015."),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015.a"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015.0a"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015a"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015-"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015+"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015+01"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015+01000"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015+0100a"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015-01000"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015-0100a"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015.1234567890Z"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015+0160"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015+2400"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
            }
        }
    }
}
