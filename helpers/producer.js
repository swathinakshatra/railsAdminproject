const Queue = require('bull');
const jobQueue = new Queue("job-queue", {
  redis: {
    host: "127.0.0.1",
    port: 6379,
  },
});

const addJob = async (data, priority) => {
  try {
    const job = await jobQueue.add(data, { priority });
    console.log(`Job added to queue: ${job.id}`);
    return job;
  } catch (error) {
    console.error(error);
    throw error;
  }
};

module.exports = addJob;

module.exports = addJob;
