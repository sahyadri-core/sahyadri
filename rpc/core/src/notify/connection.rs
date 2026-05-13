use crate::Notification;

pub type ChannelConnection = sahyadri_notify::connection::ChannelConnection<Notification>;
pub use sahyadri_notify::connection::ChannelType;
