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
    fn append(self, packet: &mut Packet) -> Result<()> {
        packet.put_u8(match self {
            Self::Open => 0,
            Self::HiddenByAdmin => 10,
            Self::HiddenByStaff => 20,
        })?;
        Ok(())
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
    fn append(self, packet: &mut Packet) -> Result<()> {
        packet.put_i32(match self {
            Self::MostActive => 0,
            Self::MostRead => 1,
            Self::MyForums => 2,
        })?;
        Ok(())
    }
}

fn append_count(packet: &mut Packet, len: usize) -> Result<()> {
    if len > 65_536 {
        return Err(error("forum count exceeds limit"));
    }
    packet.put_i32(len as i32)?;
    Ok(())
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
    pub fn append(&self, p: &mut Packet) -> Result<()> {
        p.put_i32(self.comment_id)?
            .put_i32(self.index_in_thread)?
            .put_i32(self.user_id)?
            .put_string(&self.user_name)?
            .put_string(&self.look)?
            .put_i32(self.passed_time)?
            .put_string(&self.message)?;
        self.state.append(p)?;
        p.put_i32(self.admin_id)?
            .put_string(&self.admin_name)?
            .put_i32(self.unknown_id)?
            .put_i32(self.author_post_count)?;
        Ok(())
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
    pub fn append(&self, p: &mut Packet) -> Result<()> {
        if self.comments.len() > 65_536 {
            return Err(error("forum count exceeds limit"));
        }
        p.put_i32(self.guild_id)?
            .put_i32(self.thread_id)?
            .put_i32(self.start_index)?;
        append_count(p, self.comments.len())?;
        for comment in &self.comments {
            comment.append(p)?;
        }
        Ok(())
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
    pub fn append(&self, p: &mut Packet) -> Result<()> {
        p.put_i32(self.guild_id)?
            .put_string(&self.guild_name)?
            .put_string(&self.guild_description)?
            .put_string(&self.guild_badge)?
            .put_i32(self.unknown)?
            .put_i32(self.rating)?
            .put_i32(self.comment_count)?
            .put_i32(self.unread_comments)?
            .put_i32(self.last_comment_index)?
            .put_i32(self.last_comment_user_id)?
            .put_string(&self.last_comment_user_name)?
            .put_i32(self.last_comment_passed_time)?;
        Ok(())
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
    pub fn append(&self, p: &mut Packet) -> Result<()> {
        if self.forums.len() > 65_536 {
            return Err(error("forum count exceeds limit"));
        }
        self.view_mode.append(p)?;
        p.put_i32(self.size)?.put_i32(self.start_index)?;
        append_count(p, self.forums.len())?;
        for forum in &self.forums {
            forum.append(p)?;
        }
        Ok(())
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
    pub fn append(&self, p: &mut Packet) -> Result<()> {
        p.put_i32(self.thread_id)?
            .put_i32(self.author_id)?
            .put_string(&self.author_name)?
            .put_string(&self.subject)?
            .put_bool(self.pinned)?
            .put_bool(self.locked)?
            .put_i32(self.passed_time)?
            .put_i32(self.comment_count)?
            .put_i32(self.unread_comments)?
            .put_i32(self.last_comment_index)?
            .put_i32(self.last_comment_author_id)?
            .put_string(&self.last_comment_author_name)?
            .put_i32(self.last_comment_passed_time)?;
        self.state.append(p)?;
        p.put_i32(self.admin_id)?
            .put_string(&self.admin_name)?
            .put_i32(self.unknown_thread_id)?;
        Ok(())
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
    pub fn append(&self, p: &mut Packet) -> Result<()> {
        if self.threads.len() > 65_536 {
            return Err(error("forum count exceeds limit"));
        }
        p.put_i32(self.guild_id)?.put_i32(self.start_index)?;
        append_count(p, self.threads.len())?;
        for thread in &self.threads {
            thread.append(p)?;
        }
        Ok(())
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
        let mut encoded = Packet::new(1);
        overview.append(&mut encoded).unwrap();
        assert_eq!(p.bytes(), encoded.bytes());
    }

    #[test]
    fn forum_and_thread_overviews_roundtrip() {
        let forums = ForumOverview {
            view_mode: ForumOverviewType::MostRead,
            size: 12,
            start_index: 4,
            forums: vec![Forum {
                guild_id: 42,
                guild_name: "Habbo".into(),
                guild_description: "Description".into(),
                guild_badge: "ABC".into(),
                unknown: 4,
                rating: 5,
                comment_count: 6,
                unread_comments: 7,
                last_comment_index: 8,
                last_comment_user_id: 9,
                last_comment_user_name: "Alice".into(),
                last_comment_passed_time: 10,
            }],
        };
        let mut packet = Packet::new(1);
        forums.append(&mut packet).unwrap();
        assert_eq!(ForumOverview::read(&mut packet).unwrap(), forums);

        let threads = ThreadOverview {
            guild_id: 42,
            start_index: 3,
            threads: vec![Thread {
                thread_id: 1,
                author_id: 2,
                author_name: "Alice".into(),
                subject: "Hello".into(),
                pinned: true,
                locked: false,
                passed_time: 3,
                comment_count: 4,
                unread_comments: 5,
                last_comment_index: 6,
                last_comment_author_id: 7,
                last_comment_author_name: "Bob".into(),
                last_comment_passed_time: 8,
                state: ThreadState::HiddenByStaff,
                admin_id: 9,
                admin_name: "Mod".into(),
                unknown_thread_id: 10,
            }],
        };
        let mut packet = Packet::new(1);
        threads.append(&mut packet).unwrap();
        assert_eq!(ThreadOverview::read(&mut packet).unwrap(), threads);
    }
}
