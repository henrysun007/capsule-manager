pub mod policy;
pub mod request;

use crate::errno;
use crate::error::errors::{Error, ErrorCode, ErrorLocation};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Deserialize, Serialize, PartialEq, Clone)]
pub enum Operator {
    #[serde(rename = "*")]
    ANY,

    #[serde(rename = "OP_PSI")]
    PSI,

    #[serde(rename = "OP_XGB")]
    XGB,

    #[serde(rename = "OP_LR")]
    LR,

    #[serde(rename = "OP_DATASET_FILTER")]
    DatasetFilter,

    #[serde(rename = "OP_DATASET_SPLIT")]
    DatasetSplit,

    #[serde(rename = "OP_STATS_CORR")]
    StatsCorr,

    #[serde(rename = "OP_STATS_VIF")]
    StatsVif,

    #[serde(rename = "OP_TABLE_STATISTICS")]
    TableStatistics,

    #[serde(rename = "OP_WOE_BINNING")]
    WoeBinning,

    #[serde(rename = "OP_WOE_SUBSTITUTION")]
    WoeSubstitution,

    #[serde(rename = "OP_BICLASSIFIER_EVALUATION")]
    BiclassifierEvaluation,

    #[serde(rename = "OP_PREDICT")]
    Predict,

    #[serde(rename = "OP_PREDICTION_BIAS_EVALUATION")]
    PredictionBiasEvaluation,

    #[serde(rename = "OP_SQL")]
    Sql,

    #[serde(rename = "OP_PYTHON")]
    Python,
}

impl fmt::Debug for Operator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Operator::ANY => write!(f, "*"),
            Operator::PSI => write!(f, "OP_PSI"),
            Operator::XGB => write!(f, "OP_XGB"),
            Operator::LR => write!(f, "OP_LR"),
            Operator::DatasetFilter => write!(f, "OP_DATASET_FILTER"),
            Operator::DatasetSplit => write!(f, "OP_DATASET_SPLIT"),
            Operator::StatsCorr => write!(f, "OP_STATS_CORR"),
            Operator::StatsVif => write!(f, "OP_STATS_VIF"),
            Operator::TableStatistics => write!(f, "OP_TABLE_STATISTICS"),
            Operator::WoeBinning => write!(f, "OP_WOE_BINNING"),
            Operator::WoeSubstitution => write!(f, "OP_WOE_SUBSTITUTION"),
            Operator::BiclassifierEvaluation => write!(f, "OP_BICLASSIFIER_EVALUATION"),
            Operator::Predict => write!(f, "OP_PREDICT"),
            Operator::PredictionBiasEvaluation => write!(f, "OP_PREDICTION_BIAS_EVALUATION"),
            Operator::Sql => write!(f, "OP_SQL"),
            Operator::Python => write!(f, "OP_PYTHON"),
        }
    }
}

impl FromStr for Operator {
    type Err = ();

    fn from_str(input: &str) -> Result<Operator, Self::Err> {
        match input {
            "*" => Ok(Operator::ANY),
            "OP_PSI" => Ok(Operator::PSI),
            "OP_XGB" => Ok(Operator::XGB),
            "OP_LR" => Ok(Operator::LR),
            "OP_DATASET_FILTER" => Ok(Operator::DatasetFilter),
            "OP_DATASET_SPLIT" => Ok(Operator::DatasetSplit),
            "OP_STATS_CORR" => Ok(Operator::StatsCorr),
            "OP_STATS_VIF" => Ok(Operator::StatsVif),
            "OP_TABLE_STATISTICS" => Ok(Operator::TableStatistics),
            "OP_WOE_BINNING" => Ok(Operator::WoeBinning),
            "OP_WOE_SUBSTITUTION" => Ok(Operator::WoeSubstitution),
            "OP_BICLASSIFIER_EVALUATION" => Ok(Operator::BiclassifierEvaluation),
            "OP_PREDICT" => Ok(Operator::Predict),
            "OP_PREDICTION_BIAS_EVALUATION" => Ok(Operator::PredictionBiasEvaluation),
            "OP_SQL" => Ok(Operator::Sql),
            "OP_PYTHON" => Ok(Operator::Python),
            _ => Err(()),
        }
    }
}

#[derive(Default)]
pub struct ResourceUri {
    pub data_uuid: String,

    pub partition_id: Option<String>,

    pub segment_id: Option<u32>,

    pub shard_id: Option<u32>,
}

impl Serialize for ResourceUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

use std::str;

impl str::FromStr for ResourceUri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split_strs = s.split('/').collect::<Vec<&str>>();
        let mut uri = ResourceUri::default();
        for (i, &part) in split_strs.iter().enumerate() {
            if i == 0 {
                if part.is_empty() {
                    return Err(errno!(ErrorCode::InvalidArgument, "data uuid is empty"));
                }
                uri.data_uuid = part.to_owned();
            } else if i == 1 {
                match part.is_empty() {
                    true => break,
                    false => uri.partition_id = Some(part.to_owned()),
                }
            } else if i == 2 {
                match part.is_empty() {
                    true => break,
                    false => {
                        uri.segment_id = Some(part.parse().map_err(|e| {
                            errno!(ErrorCode::InvalidArgument, "parse int failed, {:?}", e)
                        })?)
                    }
                }
            } else if i == 3 {
                match part.is_empty() {
                    true => break,
                    false => {
                        uri.shard_id = Some(part.parse().map_err(|e| {
                            errno!(ErrorCode::InvalidArgument, "parse int failed, {:?}", e)
                        })?)
                    }
                }
            }
        }
        Ok(uri)
    }
}

impl fmt::Display for ResourceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut uri = self.data_uuid.clone();
        if let Some(ref partition_id) = self.partition_id {
            uri.push_str(partition_id.as_str());
            if let Some(ref segment_id) = self.segment_id {
                uri.push_str(segment_id.to_string().as_str());
                if let Some(ref shard_id) = self.shard_id {
                    uri.push_str(shard_id.to_string().as_str());
                }
            }
        }
        write!(f, "{uri}")
    }
}

// for example, "tee/download, data_uuid"
#[derive(Default, Debug)]
pub struct ApproveAction {
    pub action_name: String,

    pub resource_uri: String,
}

impl str::FromStr for ApproveAction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split_strs = s.split(',').collect::<Vec<&str>>();
        let mut action = ApproveAction::default();
        for (i, &part) in split_strs.iter().enumerate() {
            if i == 0 {
                if part.is_empty() {
                    return Err(errno!(ErrorCode::InvalidArgument, "action_name is empty"));
                }
                action.action_name = part.to_owned();
            } else if i == 1 {
                if part.is_empty() {
                    return Err(errno!(ErrorCode::InvalidArgument, "resource_uri is empty"));
                }
                action.resource_uri = part.to_owned();
            } else {
                break;
            }
        }
        Ok(action)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_uri_serialization() {
        use super::ResourceUri;
        let resource_uri = ResourceUri {
            data_uuid: String::from("data_uuid"),
            partition_id: None,
            segment_id: None,
            shard_id: None,
        };
        assert_eq!(resource_uri.to_string().as_str(), "data_uuid");
    }
}
