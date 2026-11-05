//! Forum overview, thread and comment parsers from beta-29.
use crate::packet::{error, Packet, Result};
fn count(packet: &mut Packet) -> Result<usize> {
    let n = usize::try_from(packet.read_i32()?).map_err(|_| error("negative forum count"))?;
    if n > 65_536 {
        return Err(error("forum count exceeds limit"));
    }
    Ok(n)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Open,
    HiddenByAdmin,
    HiddenByStaff,
}
impl ThreadState {
    fn read(packet: &mut Packet) -> Result<Self> {
        Ok(match packet.read_u8()? {
            10 => Self::HiddenByAdmin,
            20 => Self::HiddenByStaff,
            _ => Self::Open,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForumOverviewType {
    MostActive,
    MostRead,
    MyForums,
}
impl ForumOverviewType {
    fn read(packet: &mut Packet) -> Result<Self> {
        Ok(match packet.read_i32()? {
            0 => Self::MostActive,
            1 => Self::MostRead,
            _ => Self::MyForums,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comment {
    pub comment_id: i32,
    pub index_in_thread: i32,
    pub user_id: i32,
    pub user_name: String,
    pub look: String,
    pub passed_time: i32,
    pub message: String,
    pub state: ThreadState,
    pub admin_id: i32,
    pub admin_name: String,
    pub unknown_id: i32,
    pub author_post_count: i32,
}
impl Comment {
    pub fn read(p: &mut Packet) -> Result<Self> {
        Ok(Self {
            comment_id: p.read_i32()?,
            index_in_thread: p.read_i32()?,
            user_id: p.read_i32()?,
            user_name: p.read_string()?,
            look: p.read_string()?,
            passed_time: p.read_i32()?,
            message: p.read_string()?,
            state: ThreadState::read(p)?,
            admin_id: p.read_i32()?,
            admin_name: p.read_string()?,
            unknown_id: p.read_i32()?,
            author_post_count: p.read_i32()?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommentOverview {
    pub guild_id: i32,
    pub thread_id: i32,
    pub start_index: i32,
    pub comments: Vec<Comment>,
}
impl CommentOverview {
    pub fn read(p: &mut Packet) -> Result<Self> {
        let guild_id = p.read_i32()?;
        let thread_id = p.read_i32()?;
        let start_index = p.read_i32()?;
        let n = count(p)?;
        let mut comments = Vec::with_capacity(n);
        for _ in 0..n {
            comments.push(Comment::read(p)?);
        }
        Ok(Self {
            guild_id,
            thread_id,
            start_index,
            comments,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forum {
    pub guild_id: i32,
    pub guild_name: String,
    pub guild_description: String,
    pub guild_badge: String,
    pub unknown: i32,
    pub rating: i32,
    pub comment_count: i32,
    pub unread_comments: i32,
    pub last_comment_index: i32,
    pub last_comment_user_id: i32,
    pub last_comment_user_name: String,
    pub last_comment_passed_time: i32,
}
impl Forum {
    pub fn read(p: &mut Packet) -> Result<Self> {
        Ok(Self {
            guild_id: p.read_i32()?,
            guild_name: p.read_string()?,
            guild_description: p.read_string()?,
            guild_badge: p.read_string()?,
            unknown: p.read_i32()?,
            rating: p.read_i32()?,
            comment_count: p.read_i32()?,
            unread_comments: p.read_i32()?,
            last_comment_index: p.read_i32()?,
            last_comment_user_id: p.read_i32()?,
            last_comment_user_name: p.read_string()?,
            last_comment_passed_time: p.read_i32()?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForumOverview {
    pub view_mode: ForumOverviewType,
    pub size: i32,
    pub start_index: i32,
    pub forums: Vec<Forum>,
}
impl ForumOverview {
    pub fn read(p: &mut Packet) -> Result<Self> {
        let view_mode = ForumOverviewType::read(p)?;
        let size = p.read_i32()?;
        let start_index = p.read_i32()?;
        let n = count(p)?;
        let mut forums = Vec::with_capacity(n);
        for _ in 0..n {
            forums.push(Forum::read(p)?);
        }
        Ok(Self {
            view_mode,
            size,
            start_index,
            forums,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thread {
    pub thread_id: i32,
    pub author_id: i32,
    pub author_name: String,
    pub subject: String,
    pub pinned: bool,
    pub locked: bool,
    pub passed_time: i32,
    pub comment_count: i32,
    pub unread_comments: i32,
    pub last_comment_index: i32,
    pub last_comment_author_id: i32,
    pub last_comment_author_name: String,
    pub last_comment_passed_time: i32,
    pub state: ThreadState,
    pub admin_id: i32,
    pub admin_name: String,
    pub unknown_thread_id: i32,
}
impl Thread {
    pub fn read(p: &mut Packet) -> Result<Self> {
        Ok(Self {
            thread_id: p.read_i32()?,
            author_id: p.read_i32()?,
            author_name: p.read_string()?,
            subject: p.read_string()?,
            pinned: p.read_bool()?,
            locked: p.read_bool()?,
            passed_time: p.read_i32()?,
            comment_count: p.read_i32()?,
            unread_comments: p.read_i32()?,
            last_comment_index: p.read_i32()?,
            last_comment_author_id: p.read_i32()?,
            last_comment_author_name: p.read_string()?,
            last_comment_passed_time: p.read_i32()?,
            state: ThreadState::read(p)?,
            admin_id: p.read_i32()?,
            admin_name: p.read_string()?,
            unknown_thread_id: p.read_i32()?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadOverview {
    pub guild_id: i32,
    pub start_index: i32,
    pub threads: Vec<Thread>,
}
impl ThreadOverview {
    pub fn read(p: &mut Packet) -> Result<Self> {
        let guild_id = p.read_i32()?;
        let start_index = p.read_i32()?;
        let n = count(p)?;
        let mut threads = Vec::with_capacity(n);
        for _ in 0..n {
            threads.push(Thread::read(p)?);
        }
        Ok(Self {
            guild_id,
            start_index,
            threads,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comment_overview_reads_state_and_metadata() {
        let mut p = Packet::new(1);
        p.put_i32(1)
            .unwrap()
            .put_i32(2)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(1)
            .unwrap()
            .put_i32(3)
            .unwrap()
            .put_i32(4)
            .unwrap()
            .put_i32(5)
            .unwrap()
            .put_string("Alice")
            .unwrap()
            .put_string("figure")
            .unwrap()
            .put_i32(6)
            .unwrap()
            .put_string("hello")
            .unwrap()
            .put_u8(10)
            .unwrap()
            .put_i32(7)
            .unwrap()
            .put_string("moderator")
            .unwrap()
            .put_i32(8)
            .unwrap()
            .put_i32(9)
            .unwrap();
        let overview = CommentOverview::read(&mut p).unwrap();
        assert_eq!(overview.comments[0].state, ThreadState::HiddenByAdmin);
        assert_eq!(overview.comments[0].message, "hello");
        assert_eq!(overview.comments[0].author_post_count, 9);
    }
}
